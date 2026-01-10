
#include <Foundation/Foundation.h>
#include <pthread.h>
#include <signal.h>
#include "common.h"
#include "ptrace.h"
#include "codesign.h"

#ifndef __MigPackStructs
#define __MigPackStructs
#endif
#include "mach_exc.h" //mig -arch arm64 -arch arm64e mach_exc.defs

static void* exception_server(void* arg)
{
    mach_port_t port = (mach_port_t)(uintptr_t)arg;

    int bufsize = 4096;
    mach_msg_header_t* msg = (mach_msg_header_t*)malloc(bufsize);
    
	while (true) {
        
        memset(msg, 0, bufsize);
        msg->msgh_size = bufsize;
        mach_msg_return_t ret = mach_msg(msg, MACH_RCV_MSG|MACH_RCV_LARGE, 0, msg->msgh_size, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

        if(ret != MACH_MSG_SUCCESS) {
            SYSERR("JIT: mach_msg error=%x", ret);
            usleep(10*1000);
            continue;
        }

        __Request__mach_exception_raise_t *request = (__Request__mach_exception_raise_t*)msg;

        __Reply__mach_exception_raise_t reply = {0};

        reply.NDR = request->NDR;
        reply.RetCode = KERN_SUCCESS;
        // reply.RetCode = KERN_FAILURE;

        pid_t pid=0;
        kern_return_t kr = pid_for_task(request->task.name, &pid);
        if(kr != KERN_SUCCESS || pid<=0) {
            SYSERR("JIT: pid_for_task (task=%x pid=%d) failed: %x, %s", request->task.name, pid, kr, mach_error_string(kr));
            continue;
        }

        arm_thread_state64_t threadState;
        mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
        thread_get_state(request->thread.name, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);

        arm_exception_state64_t exceptionState;
        mach_msg_type_number_t exceptionStateCount = ARM_EXCEPTION_STATE64_COUNT;
        thread_get_state(request->thread.name, ARM_EXCEPTION_STATE64, (thread_state_t)&exceptionState, &exceptionStateCount);
        
		__darwin_arm_thread_state64_ptrauth_strip(threadState);
        uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(threadState);

        SYSLOG("JIT: pid=%d exception: type=%d ncode=%d code=0x%llX(%lld) subcode=0x%llX(%lld) thread=%x pc=%p", pid, request->exception, request->codeCnt, 
            request->code[0], request->code[0], request->code[1], request->code[1],
            request->thread.name, (void*)pc);

        if(request->exception == EXC_SOFTWARE && request->codeCnt == 2 && request->code[0] == EXC_SOFT_SIGNAL) 
        {
            SYSLOG("JIT: got signal: %d, pid=%d,%s", (int)request->code[1], pid, proc_get_path(pid,NULL));

            switch(request->code[1]) {
                case SIGSTOP: {
                    SYSLOG("JIT: SIGSTOP received from %d,%s", pid, proc_get_path(pid,NULL));

                    // sleep(1);getchar();
                    int ret = ptrace(PT_DETACH, pid, NULL, SIGSTOP);
                    SYSLOG("JIT: PT_DETACH=%d, err=%d,%s", ret, ret==0?0:errno, ret==0?NULL:strerror(errno));

                    break;
                }

                default:
                    SYSERR("JIT: unknown signal code: %d from %d,%s", (int)request->code[1], pid, proc_get_path(pid,NULL));
                    break;
            }
        } else {
            SYSERR("JIT: unexpected exception type: %d from %d,%s", request->exception, pid, proc_get_path(pid,NULL));
        }

		reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg->msgh_bits), 0);
		reply.Head.msgh_size = sizeof(__Reply__mach_exception_raise_t);
		reply.Head.msgh_remote_port = msg->msgh_remote_port;
		reply.Head.msgh_local_port = MACH_PORT_NULL;
		reply.Head.msgh_id = msg->msgh_id + 0x64;

		mach_msg(&reply.Head, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	}
}

//don't know why this is not work with frida -f: the process is still suspended after frida attach
int proc_enable_jit_reliable(pid_t pid, bool suspended)
{
	uint32_t csflags = 0;
	if(csops(pid, CS_OPS_STATUS, &csflags, sizeof(csflags)) != 0) {
        SYSERR("JIT: csops(CS_OPS_STATUS) failed for pid=%d,%s: %d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
        return -1;
    }

    //but fork/vfork child process need to enable JIT again....
	// if((csflags & CS_DEBUGGED) != 0) {
	// 	SYSERR("JIT: process (%d,%s) has been debugged, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
	// 	return 0;
	// }

	if((csflags & CS_GET_TASK_ALLOW) == 0) {
		SYSERR("JIT: process (%d,%s) doesn't have CS_GET_TASK_ALLOW, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
		return -1;
	}

    if(suspended)
    {
        bool paused;
        if(proc_paused(pid, &paused) != 0) {
            SYSERR("JIT: proc_paused(%d,%s) failed", pid, proc_get_path(pid, NULL));
            return -1;
        }
        if(!paused) {
            SYSERR("JIT: process (%d,%s) is not paused", pid, proc_get_path(pid, NULL));
            return -1;
        }
    }

	static mach_port_t exception_port = MACH_PORT_NULL;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
    
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
        mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);

        pthread_t thread;
        pthread_create(&thread, NULL, exception_server, (void*)(uintptr_t)exception_port);

        __uint64_t tid = 0;
        pthread_threadid_np(thread, &tid);
        SYSLOG("JIT: exception_server thread: %x tid=%d", thread, tid);
	});

    mach_port_t task=MACH_PORT_NULL;

    exception_mask_t       saved_masks[EXC_TYPES_COUNT] = {0};
    mach_port_t            saved_ports[EXC_TYPES_COUNT] = {0};
    exception_behavior_t   saved_behaviors[EXC_TYPES_COUNT] = {0};
    thread_state_flavor_t  saved_flavors[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t saved_exception_types_count = 0;

    thread_act_array_t allThreads=NULL;
    mach_msg_type_number_t threadCount = 0;

	int retval = -1;
	
	if(suspended)
	{
		kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
		if(kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
			SYSERR("JIT: task_for_pid(%d,task=%x) failed: %x, %s", pid, task, kr, mach_error_string(kr));
			return -1;
		}

        mach_task_basic_info_data_t info = {0};
        mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO_COUNT;
        kr = task_info(task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count);
        if(kr == KERN_SUCCESS) {
            SYSLOG("JIT: task_info: suspend_count=%d", info.suspend_count);
        } else {
            SYSERR("JIT: task_info failed: %d,%s", kr, mach_error_string(kr));
        }

        kr = task_threads(task, &allThreads, &threadCount);
        if(kr != KERN_SUCCESS) {
            SYSERR("JIT: task_threads failed: %d,%s", kr, mach_error_string(kr));
            goto cleanup;
        }
        if(threadCount == 0) {
            SYSERR("JIT: no thread found");
            goto cleanup;
        }

        for(int i=0; i<threadCount; i++)
        {
            arm_thread_state64_t threadState={0};
            mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(allThreads[i], ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);
            if(kr == KERN_SUCCESS) {
                __darwin_arm_thread_state64_ptrauth_strip(threadState);
                uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(threadState);
                SYSLOG("JIT: allThreads[%d]=%x PC=%p", i, allThreads[i], (void*)pc);
            } else {
                SYSERR("JIT: thread_get_state failed: %d,%s", kr, mach_error_string(kr));
            }

            thread_info_data_t threadInfo={0};
            mach_msg_type_number_t threadInfoCount = THREAD_BASIC_INFO_COUNT;
            kr = thread_info(allThreads[i], THREAD_BASIC_INFO, (thread_info_t)threadInfo, &threadInfoCount);
            if(kr == KERN_SUCCESS) {
                thread_basic_info_t basicInfo = (thread_basic_info_t)threadInfo;
                SYSLOG("JIT: thread[%d] suspend_count=%d", i, basicInfo->suspend_count);
            } else {
                SYSERR("JIT: thread_info failed: %d,%s", kr, mach_error_string(kr));
            }
        }

    	kr = task_get_exception_ports(task, EXC_MASK_SOFTWARE, saved_masks, &saved_exception_types_count, saved_ports, saved_behaviors, saved_flavors);
		if(kr != KERN_SUCCESS) {
			SYSERR("JIT: task_get_exception_ports(%d,task=%x) failed: %x, %s", pid, task, kr, mach_error_string(kr));
			goto cleanup;
		}

        kr = task_set_exception_ports(task, EXC_MASK_SOFTWARE, exception_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
        if(kr != KERN_SUCCESS) {
			SYSERR("JIT: task_set_exception_ports(%d,task=%x) failed: %x, %s", pid, task, kr, mach_error_string(kr));
			goto cleanup;
		}
	}

    /* PT_ATTACHEXC on a running process doesn't really suspend it 
        if its exception port is not set, although its pstat will be set to SSTOP later. */
	retval = ptrace(PT_ATTACHEXC, pid, NULL, 0);
	if(retval != 0) {
		SYSERR("JIT: PT_ATTACHEXC(%d,%s) err=%d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
		goto cleanup;
	}

    SYSLOG("JIT: PT_ATTACHEXC(%d,%s) success", pid, proc_get_path(pid, NULL));

	bool paused=false;
	for(int i=0; i<1000*50; i++)
    {
        retval = proc_paused(pid, &paused);
        if(retval != 0) {
            SYSERR("JIT: proc_paused failed: %d,%s", pid, proc_get_path(pid, NULL));
			goto cleanup;
		}

        SYSLOG("JIT: process paused=%d", paused);
        
        if(paused) break;

		usleep(10);
	}

	if(!paused) {
		SYSERR("JIT: wait process timeout: %d,%s", pid, proc_get_path(pid, NULL));
	}

    if(!suspended)
    {
        retval = ptrace(PT_DETACH, pid, NULL, 0);
        if(retval != 0) {
            SYSERR("JIT: PT_DETACH(%d,%s) err=%d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
            goto cleanup;
        }

        SYSLOG("JIT: PT_DETACH(%d,%s) success", pid, proc_get_path(pid, NULL));
    }
    else
    {
        bool paused2=false;
        for(int i=0; i<1000*50; i++)
        {
            retval = proc_paused(pid, &paused2);
            if(retval != 0) {
                SYSERR("JIT: proc_paused failed: %d,%s", pid, proc_get_path(pid, NULL));
                goto cleanup;
            }

            bool traced = proc_traced(pid);

            SYSLOG("JIT: process paused2=%d, traced=%d", paused2, traced);
            
            if(!traced && paused2) break;

            usleep(10);
        }

        if(!paused2) {
            SYSERR("JIT: wait process timeout2: %d,%s", pid, proc_get_path(pid, NULL));
            retval = -1;
            goto cleanup;
        }
    }

cleanup:

    if(suspended)
    {
        mach_task_basic_info_data_t info = {0};
        mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO_COUNT;
        kern_return_t kr = task_info(task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count);
        if(kr == KERN_SUCCESS) {
            SYSLOG("JIT: task_info: suspend_count2=%d", info.suspend_count);
        } else {
            SYSERR("JIT: task_info failed2: %d,%s", kr, mach_error_string(kr));
        }

        for(int i=0; i<threadCount; i++)
        {
            arm_thread_state64_t threadState={0};
            mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
            kern_return_t kr = thread_get_state(allThreads[i], ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);
            if(kr == KERN_SUCCESS) {
                __darwin_arm_thread_state64_ptrauth_strip(threadState);
                uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(threadState);
                SYSLOG("JIT: allThreads[%d]=%x PC=%p", i, allThreads[i], (void*)pc);
            } else {
                SYSERR("JIT: thread_get_state failed: %d,%s", kr, mach_error_string(kr));
            }
            
            thread_info_data_t threadInfo={0};
            mach_msg_type_number_t threadInfoCount = THREAD_BASIC_INFO_COUNT;
            kr = thread_info(allThreads[i], THREAD_BASIC_INFO, (thread_info_t)threadInfo, &threadInfoCount);
            if(kr == KERN_SUCCESS) {
                thread_basic_info_t basicInfo = (thread_basic_info_t)threadInfo;
                SYSLOG("JIT: thread[%d] suspend_count=%d", i, basicInfo->suspend_count);
            } else {
                SYSERR("JIT: thread_info failed2: %d,%s", kr, mach_error_string(kr));
            }
        }

        for(int i=0; i<threadCount; i++) {
            mach_port_deallocate(mach_task_self(), allThreads[i]);
        }
        if(allThreads) {
            vm_deallocate(mach_task_self(), (mach_vm_address_t)allThreads, threadCount*sizeof(allThreads[0]));
        }

        for (uint32_t i = 0; i < saved_exception_types_count; ++i) {
            kern_return_t kr = task_set_exception_ports(task, saved_masks[i], saved_ports[i], saved_behaviors[i], saved_flavors[i]);
            if(kr != KERN_SUCCESS) {
                SYSERR("JIT: task_set_exception_ports[%d] failed: %x, %s\n", i, kr, mach_error_string(kr));
            }
        }

        for (uint32_t i = 0; i < saved_exception_types_count; ++i) {
            if(MACH_PORT_VALID(saved_ports[i])) {
                mach_port_deallocate(mach_task_self(), saved_ports[i]);
            }
        }

        if(MACH_PORT_VALID(task)) {
            mach_port_deallocate(mach_task_self(), task);
        }
    }

	return retval;
}


/* A quick PT_ATTACHEXC + PT_DETACH on a suspended process may resume execution or remain suspended,
     depending on when the kernel actually handles the signal, so it is not 100% reliable. */
int proc_enable_jit_unreliable(pid_t pid, bool suspended)
{
	uint32_t csflags = 0;
	if(csops(pid, CS_OPS_STATUS, &csflags, sizeof(csflags)) != 0) {
        SYSERR("JIT: csops(CS_OPS_STATUS) failed for pid=%d,%s: %d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
        return -1;
    }

    //but fork/vfork child process need to enable JIT again....
	// if((csflags & CS_DEBUGGED) != 0) {
	// 	SYSERR("JIT: process (%d,%s) has been debugged, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
	// 	return 0;
	// }

	if((csflags & CS_GET_TASK_ALLOW) == 0) {
		SYSERR("JIT: process (%d,%s) doesn't have CS_GET_TASK_ALLOW, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
		return -1;
	}

    if(suspended)
    {
        bool paused;
        if(proc_paused(pid, &paused) != 0) {
            SYSERR("JIT: proc_paused(%d,%s) failed", pid, proc_get_path(pid, NULL));
            return -1;
        }
        if(!paused) {
            SYSERR("JIT: process (%d,%s) is not paused", pid, proc_get_path(pid, NULL));
            return -1;
        }
    }

    /* PT_ATTACHEXC on a running process doesn't really suspend it 
        if its exception port is not set, although its pstat will be set to SSTOP later. */
	int ret = ptrace(PT_ATTACHEXC, pid, NULL, 0);
	if(ret != 0) {
		SYSERR("JIT: PT_ATTACHEXC(%d,%s) err = %d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
		return -1;
	}

    SYSLOG("JIT: PT_ATTACHEXC(%d,%s) success", pid, proc_get_path(pid, NULL));

	bool paused=false;
	for(int i=0; i<1000*50; i++)
    {
        ret = proc_paused(pid, &paused);
        if(ret != 0) {
            SYSERR("JIT: proc_paused failed: %d,%s", pid, proc_get_path(pid, NULL));
			return -1;
		}

        SYSLOG("JIT: process paused=%d", paused);
        
        if(paused) break;

		usleep(10);
	}

	if(!paused) {
		SYSERR("JIT: wait process timeout: %d,%s", pid, proc_get_path(pid, NULL));
	}

    // if(suspended) sleep(1); getchar(); //test
	
    ret = ptrace(PT_DETACH, pid, NULL, 0);
	if(ret != 0) {
		SYSERR("JIT: PT_DETACH(%d,%s) err=%d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
		return -1;
	}

    SYSLOG("JIT: PT_DETACH(%d,%s) success", pid, proc_get_path(pid, NULL));

    if(suspended)
    {
        bool paused2=false;
        for(int i=0; i<1000*50; i++)
        {
            ret = proc_paused(pid, &paused2);
            SYSLOG("JIT: process paused2=%d, %d", ret, paused2);
            
            if(ret != 0) {
                return -1;
            }
            
            if(paused2) break;

            usleep(10);
        }

        if(!paused2) {
            SYSERR("JIT: wait process timeout2: %d,%s", pid, proc_get_path(pid, NULL));
            return -1; //the suspended process may have been resumed by PT_ATTACHEXC
        }
    }

	return ret;
}

int proc_enable_jit(pid_t pid, bool suspended)
{
    return proc_enable_jit_unreliable(pid, suspended);
}
