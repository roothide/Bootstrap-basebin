//
// Created by Ylarod on 2024/3/15.
//

#include <sys/event.h>
#include <dispatch/dispatch.h>
#import <Foundation/Foundation.h>

#include "filelog.h"
#include "commlib.h"
#include "exec_patch.h"

int kq = -1;
dispatch_queue_t gExecPatchDataQueue = nil;
NSMutableDictionary *gExecPatchArray = nil;

void event_handler(int kq)
{
    while(true)
    {
        struct kevent event = {0};
        int ret = kevent(kq, NULL, 0, &event, 1, NULL);
        assert(ret == 1);
        assert(event.filter == EVFILT_PROC);

        pid_t pid = (pid_t)event.ident;

        __block NSNumber* resume;
        dispatch_sync(gExecPatchDataQueue, ^{
            resume = gExecPatchArray[@(pid)];
        });

        if(!resume) {
            FileLogError("[execPatch] no record for process: %d", pid);
            continue;
        }

        if(event.fflags & NOTE_EXIT)
        {
            FileLogError("kevent: unexpected process exit: %d", pid);
        }
        else if(event.fflags & NOTE_EXEC)
        {
            FileLogDebug("kevent: process exec: %d", pid);
            if(proc_hook_dyld(pid) == 0) {
                if (resume.boolValue) kill(pid, SIGCONT);
            } else {
                FileLogError("[execPatch] failed to patch for process: %d", pid);
                //we hosted the spawned(SETEXEC) process so we have to deal with it if patching failed
                kill(pid, SIGQUIT); //core dump
                kill(pid, SIGKILL);
            }
        }

        dispatch_sync(gExecPatchDataQueue, ^{
            [gExecPatchArray removeObjectForKey:@(pid)];
        });

    }
}

void initExecPatch() 
{
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gExecPatchArray = [[NSMutableDictionary alloc] init];
        gExecPatchDataQueue = dispatch_queue_create("roothide.execpatch.data-queue", DISPATCH_QUEUE_SERIAL);

        kq = kqueue();
        assert(kq != -1);

        queue = dispatch_queue_create("roothide.execpatch.event-queue", DISPATCH_QUEUE_SERIAL);
        dispatch_async(queue, ^{
            event_handler(kq);
        });
    });
}

int spawnExecPatchAdd(int pid, bool resume)
{
    initExecPatch();

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXEC|NOTE_EXIT, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        FileLogError("add kevent failed for pid: %d", pid);
        return -1;
    }

    dispatch_async(gExecPatchDataQueue, ^{
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            FileLogError("[spawnExecPatchAdd] already has record for process: %d", pid);
        }
        [gExecPatchArray setObject:@(resume) forKey:@(pid)];
    });
    return 0;
}

int spawnExecPatchDel(int pid)
{
    initExecPatch();

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        FileLogError("delete kevent failed for pid: %d", pid);
        return -1;
    }

    __block int ret = -1;

    //synchronous deletion
    dispatch_sync(gExecPatchDataQueue, ^{
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            [gExecPatchArray removeObjectForKey:@(pid)];
            ret = 0;
        } else {
            FileLogError("[spawnExecPatchDel] no record for process: %d", pid);
        }
    });

    return ret;
}
