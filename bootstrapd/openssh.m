
#include <Foundation/Foundation.h>
#include <spawn.h>
#include <roothide.h>
#include "envbuf.h"
#include "common.h"

bool sshenable=false;
int restartick=0;
pid_t sshdpid=0;

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
            
            int ret = spawn(jbroot(argv[0]), (char*const*)argv, (char*const*)envc, ^(pid_t pid) {
                FILE* fp = fopen(jbroot("/basebin/.sshd.pid"), "w");
                ASSERT(fp != NULL);
                fprintf(fp, "%d", pid);
                fclose(fp);

                sshdpid = pid;

            }, nil, nil);

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