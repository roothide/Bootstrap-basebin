//
//  launch.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 31/10/25.
//

@import Foundation;
#import "Header.h"
#import <mach-o/dyld.h>

pid_t launchTest(NSString *excPortName, NSString *arg1, BOOL suspended) {
    printf("Launching %s, port=%s, suspend=%d\n", arg1.UTF8String, excPortName.UTF8String, suspended);
	uint32_t execPathSize = PATH_MAX;
    char executablePath[execPathSize];
	_NSGetExecutablePath(executablePath, &execPathSize);
    
    NSString *execPath = @(executablePath);
    NSString *bundleID = @"com.kdt.taskporthaxx.xpcproxy";


    NSDictionary *plist = @{
#if DTSECURITY_WAIT_FOR_DEBUGGER
        @"WaitForDebugger": @(suspended),
#endif
        @"ProcessType": @"SystemApp",
        @"EnableTransactions": @NO,
        @"_ManagedBy": @"com.apple.runningboard",
        @"CFBundleIdentifier": bundleID,
        @"ThrottleInterval": @(2147483647),
        @"PersonaEnterprise": @(1000),
        @"EnablePressuredExit": @NO,
        @"InitialTaskRole": @(1),
        @"UserName": @"root",
        @"ExitTimeOut": @(1),
        @"Label": [NSString stringWithFormat:@"UIKitApplication:%@[%d]",
                   bundleID, arc4random_uniform(10000)],
        @"MaterializeDatalessFiles": @YES,
        //@"Program": execPath,
        @"ProgramArguments": arg1 ? @[ execPath, @"xpcproxy", arg1 ] : @[ execPath ],
        @"MachServices": @{},
        @"EnvironmentVariables": @{
            @"TMPDIR": @"/var/tmp",
            @"HOME": @"/var/root",
            @"CFFIXED_USER_HOME": @"/var/root",
            @"HAXX_EXCEPTION_PORT_NAME": excPortName,
            @"HAXX_START_SUSPENDED": suspended ? @"1" : @"0",
        },
        @"_AdditionalProperties": arg1 ? @{} : @{
            @"RunningBoard": @{
                @"Managed": @YES,
                @"RunningBoardLaunched": @YES,
                @"RunningBoardLaunchedIdentity": @{
                    @"TYPE": @(3),
                    @"EAI": bundleID
                }
            }
        }
    };
    NSDictionary *root = @{
        @"monitor": @NO,
        @"handle": @(0),
        @"type": @(7),
        @"plist": plist
    };
    
    // Convert to xpc_object_t
    xpc_object_t xpcDict = _CFXPCCreateXPCObjectFromCFObject(root);
    // For some reason _CFXPCCreateXPCObjectFromCFObject doesn't produce correct uint64, so we set them again here
    xpc_dictionary_set_uint64(xpcDict, "handle", 0);
    xpc_dictionary_set_uint64(xpcDict, "type", 7);
    
    xpc_object_t result;
    kern_return_t kr = _launch_job_routine(0x3e8, xpcDict, &result);
    printf("Launch job(%s) routine returned: %s -> %s\n\n", arg1.UTF8String, mach_error_string(kr), xpc_copy_description(result));
    
    pid_t launched_pid = -1;
    if (kr == KERN_SUCCESS && result && xpc_get_type(result) == XPC_TYPE_DICTIONARY) {
        launched_pid = (pid_t)xpc_dictionary_get_int64(result, "pid");
    }

    return launched_pid;
}
