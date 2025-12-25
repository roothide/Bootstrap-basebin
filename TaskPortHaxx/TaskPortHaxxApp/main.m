//
//  main.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 24/10/25.
//

#import <IOKit/IOKitLib.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import "Header.h"
#import "unarchive.h"

int child_execve(char *exceptionPortName, char *path) {
    mach_port_t exception_port = MACH_PORT_NULL;
    mach_port_t fake_bootstrap_port = MACH_PORT_NULL;
    bootstrap_look_up(bootstrap_port, exceptionPortName, &exception_port);
    assert(exception_port != MACH_PORT_NULL);
    bootstrap_look_up(bootstrap_port, "com.kdt.taskporthaxx.fake_bootstrap_port", &fake_bootstrap_port);
    assert(fake_bootstrap_port != MACH_PORT_NULL);
    
    task_set_exception_ports(mach_task_self(),
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64);
    mach_port_t bootstrapPort = bootstrap_port;
    task_set_bootstrap_port(mach_task_self(), fake_bootstrap_port);
    
    posix_spawnattr_t attr;
    if(posix_spawnattr_init(&attr) != 0) {
        perror("posix_spawnattr_init");
        return 1;
    }
    
    if(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC) != 0) {
        perror("posix_spawnattr_set_flags");
        return 1;
    }
    
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){0, bootstrapPort, fake_bootstrap_port}, 3);
    posix_spawnattr_setexceptionports_np(&attr,
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    char *argv2[] = { path, NULL };
    posix_spawn(NULL, argv2[0], NULL, &attr, argv2, environ);
    perror("posix_spawn");
    return 1;
}

int load_trust_cache(NSString *tcPath) {
    NSData *tcData = [NSData dataWithContentsOfFile:tcPath];
    if (!tcData) {
        printf("Trust cache file not found: %s\n", tcPath.fileSystemRepresentation);
        return 1;
    }
    CFDictionaryRef match = IOServiceMatching("AppleMobileFileIntegrity");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    io_connect_t conn;
    IOServiceOpen(svc, mach_task_self_, 0, &conn);
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, tcData.bytes, tcData.length, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("IOConnectCallMethod failed: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("Loaded trust cache from %s\n", tcPath.fileSystemRepresentation);
    IOServiceClose(conn);
    IOObjectRelease(svc);
    return 0;
}

int child_stage1_prepare(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *outDir = [fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
    NSString *zipPath = [outDir stringByAppendingPathComponent:@"UpdateBrainService.zip"];
    NSString *assetDir = [outDir stringByAppendingPathComponent:@"AssetData"];
    
    if ([fm fileExistsAtPath:zipPath] || ![fm fileExistsAtPath:assetDir]) {
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
        extract(zipPath, outDir, NULL);
        [NSFileManager.defaultManager removeItemAtPath:zipPath error:nil];
    }
    
    // Copy xpc service
    NSString *execDir = @"/var/db/com.apple.xpc.roleaccountd.staging/exec";
    [fm createDirectoryAtPath:execDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *xpcName = @"com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc";
    NSString *outXPCPath = [execDir stringByAppendingPathComponent:xpcName];
    if (![fm fileExistsAtPath:outXPCPath]) {
        NSError *error = nil;
        [fm copyItemAtPath:[assetDir stringByAppendingPathComponent:xpcName] toPath:outXPCPath error:&error];
        if (error) {
            NSLog(@"Failed to copy UpdateBrainService.xpc: %@", error);
            return 1;
        }
    }
    
    printf("Stage 1 setup complete\n");
    return 0;
}

int main(int argc, char * argv[]) {
    if(argc == 1) {
        NSString * appDelegateClassName;
        @autoreleasepool {
            // Setup code that might create autoreleased objects goes here.
            appDelegateClassName = NSStringFromClass([AppDelegate class]);
        }
        return UIApplicationMain(argc, argv, nil, appDelegateClassName);
    }
    
#if !DTSECURITY_WAIT_FOR_DEBUGGER
    char *startSuspended = getenv("HAXX_START_SUSPENDED");
    if (startSuspended && atoi(startSuspended)) {
        usleep(100000); // FIXME: how to sleep until ptrace attach?
    }
#endif
    
    if (strcmp(argv[1], "dtsecurity") == 0) {
        NSString *execDir = @"/var/db/com.apple.xpc.roleaccountd.staging/exec";
        [NSFileManager.defaultManager createDirectoryAtPath:execDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *outDir = @"/var/db/com.apple.xpc.roleaccountd.staging/exec/TaskPortHaxx.xpc";
        if (![[NSFileManager defaultManager] fileExistsAtPath:outDir]) {
            NSError *error = nil;
            [NSFileManager.defaultManager copyItemAtPath:@"/System/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/XPCServices/com.apple.dt.instruments.dtsecurity.xpc" toPath:outDir error:&error];
            if (error) {
                NSLog(@"Failed to copy dtsecurity.xpc: %@", error);
                return 1;
            }
        }
        char *portName = getenv("HAXX_EXCEPTION_PORT_NAME");
        char *path = "/var/db/com.apple.xpc.roleaccountd.staging/exec/TaskPortHaxx.xpc/com.apple.dt.instruments.dtsecurity";
        return child_execve(portName, path);
    } else if (strcmp(argv[1], "updatebrain") == 0) {
        char *portName = getenv("HAXX_EXCEPTION_PORT_NAME");
        char *path = "/var/db/com.apple.xpc.roleaccountd.staging/exec/com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc/com.apple.MobileSoftwareUpdate.UpdateBrainService";
        return child_execve(portName, path);
    } else if (strcmp(argv[1], "updatebrain-prepare") == 0) {
        return child_stage1_prepare();
    }
    //    if (getuid() != 0) {
    //        launchTest(nil);
    //        return 0;
    //    }
    
}
