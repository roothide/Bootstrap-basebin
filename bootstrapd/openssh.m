
#include <Foundation/Foundation.h>
#include <spawn.h>
#include <roothide.h>
#include "envbuf.h"
#include "assert.h"


bool sshenable=false;
int restartick=0;
pid_t sshdpid=0;

extern const char** environ;
#define SYSLOG(fmt,...) NSLog(@fmt,__VA_ARGS__)
int spawn(pid_t* pidp, const char* path, char*const* argv, char*const* envp, void(^std_out)(char*), void(^std_err)(char*))
{
    SYSLOG("spawn %s", path);
    
    __block pid_t pid=0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);

    int outPipe[2];
    pipe(outPipe);
    posix_spawn_file_actions_addclose(&action, outPipe[0]);
    posix_spawn_file_actions_adddup2(&action, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&action, outPipe[1]);
    
    int errPipe[2];
    pipe(errPipe);
    posix_spawn_file_actions_addclose(&action, errPipe[0]);
    posix_spawn_file_actions_adddup2(&action, errPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&action, errPipe[1]);

    
    dispatch_semaphore_t lock = dispatch_semaphore_create(0);
    
    dispatch_queue_t queue = dispatch_queue_create("spawnPipeQueue", DISPATCH_QUEUE_CONCURRENT);
    
    dispatch_source_t stdOutSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, outPipe[0], 0, queue);
    dispatch_source_t stdErrSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, errPipe[0], 0, queue);
    
    int outFD = outPipe[0];
    int errFD = errPipe[0];
    
    dispatch_source_set_cancel_handler(stdOutSource, ^{
        close(outFD);
        dispatch_semaphore_signal(lock);
        SYSLOG("stdout canceled [%d]", pid);
    });
    dispatch_source_set_cancel_handler(stdErrSource, ^{
        close(errFD);
        dispatch_semaphore_signal(lock);
        SYSLOG("stderr canceled [%d]", pid);
    });
    
    dispatch_source_set_event_handler(stdOutSource, ^{
        char buffer[BUFSIZ]={0};
        ssize_t bytes = read(outFD, buffer, sizeof(buffer)-1);
        if (bytes <= 0) {
            dispatch_source_cancel(stdOutSource);
            return;
        }
        SYSLOG("spawn[%d] stdout: %s", pid, buffer);
        if(std_out) std_out(buffer);
    });
    dispatch_source_set_event_handler(stdErrSource, ^{
        char buffer[BUFSIZ]={0};
        ssize_t bytes = read(errFD, buffer, sizeof(buffer)-1);
        if (bytes <= 0) {
            dispatch_source_cancel(stdErrSource);
            return;
        }
        SYSLOG("spawn[%d] stderr: %s", pid, buffer);
        if(std_err) std_err(buffer);
    });
    
    dispatch_resume(stdOutSource);
    dispatch_resume(stdErrSource);
    
    int spawnError = posix_spawn(&pid, path, &action, &attr, argv, envp);
    SYSLOG("spawn ret=%d, pid=%d", spawnError, pid);
    
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&action);
    
    close(outPipe[1]);
    close(errPipe[1]);
    
    if(spawnError != 0)
    {
        SYSLOG("posix_spawn error %d:%s\n", spawnError, strerror(spawnError));
        dispatch_source_cancel(stdOutSource);
        dispatch_source_cancel(stdErrSource);
        return spawnError;
    }

    FILE* fp = fopen(jbroot("/basebin/.sshd.pid"), "w");
    ASSERT(fp != NULL);
    fprintf(fp, "%d", pid);
    fclose(fp);
    
    if(pidp) *pidp = pid;
    
    //wait stdout
    dispatch_semaphore_wait(lock, DISPATCH_TIME_FOREVER);
    //wait stderr
    dispatch_semaphore_wait(lock, DISPATCH_TIME_FOREVER);
    
    int status=0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        //keep waiting?return status;
    };
    return -1;
}


int openssh_start()
{
    if(sshenable) return -1;

    sshenable = true;
    restartick = 0;

    if(sshdpid==0) 
    {
        FILE* fp = fopen(jbroot("/basebin/.sshd.pid"), "r");
        if(fp) {
            pid_t pid=0;
            fscanf(fp, "%d", &pid);
            if(pid > 0) {
                int killed = kill(pid, 0);
                if(killed==0) {
                    kill(pid, SIGKILL);
                    sleep(1);
                }
            }
            fclose(fp);
        }
    }

    dispatch_async(dispatch_get_global_queue(0,0), ^{
        while(sshenable)
        {
            char* argv[] = {
                "/bin/sh",
                "/usr/libexec/sshd-keygen-wrapper",
                "-D",
                // "-p", "2222",
                NULL
            };

            char **envc = envbuf_mutcopy(environ);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", jbroot("/basebin/bootstrap.dylib"), 1);
            
            int ret = spawn(&sshdpid, jbroot(argv[0]), (char*const*)argv, (char*const*)envc, NULL, NULL);

            envbuf_free(envc);

            restartick++;

            if(restartick <= 2)
                continue;
            
            if(restartick <= 10)
                sleep(restartick);
            else
                sleep(30);
        }
    });

    sleep(1);

    if(sshdpid <= 0) return -1;

    return 0;
}

int openssh_stop()
{
    if(!sshenable)
    {
        FILE* fp = fopen(jbroot("/basebin/.sshd.pid"), "r");
        if(fp) {
            pid_t pid=0;
            fscanf(fp, "%d", &pid);
            if(pid > 0) {
                int killed = kill(pid, 0);
                if(killed==0) {
                    kill(pid, SIGKILL);
                    return 0;
                }
            }
            fclose(fp);
        }
    }

    if(!sshenable) return -1;
    if(sshdpid<=0) return -1;
    sshenable = false;
    
    int status = kill(sshdpid,0);
    if(status==0) {
        if(kill(sshdpid, SIGTERM)!= 0) {
            return -1;
        }
    }

    sshdpid = 0;

    return 0;
}

int openssh_check()
{
    if(!sshenable)
    {
        FILE* fp = fopen(jbroot("/basebin/.sshd.pid"), "r");
        if(fp) {
            pid_t pid=0;
            fscanf(fp, "%d", &pid);
            if(pid > 0) {
                int killed = kill(pid, 0);
                if(killed==0) {
                    return 0;
                }
            }
            fclose(fp);
        }
    }

    if(sshenable && sshdpid>0)
        return 0;
    else
        return -1;
}