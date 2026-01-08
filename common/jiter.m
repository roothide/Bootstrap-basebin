
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
            SYSERR("JIT: mach_msg error=%x\n", ret);
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
            SYSERR("JIT: pid_for_task (task=%x pid=%d) failed: %x, %s\n", request->task.name, pid, kr, mach_error_string(kr));
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

        SYSLOG("JIT: pid=%d exception: type=%d ncode=%d code=0x%llX(%lld) subcode=0x%llX(%lld) thread=%x pc=%p\n", pid, request->exception, request->codeCnt, 
            request->code[0], request->code[0], request->code[1], request->code[1],
            request->thread.name, (void*)pc);

        if(request->exception == EXC_SOFTWARE && request->codeCnt == 2 && request->code[0] == EXC_SOFT_SIGNAL) 
        {
            SYSLOG("JIT: exec* pid=%d got signal: %d\n", pid, (int)request->code[1]);

            switch(request->code[1]) {
                case SIGSTOP: {
                    break;
                }

                default:
                    SYSERR("JIT: unknown signal code: %d from %d,%s\n", (int)request->code[1], pid);
                    break;
            }
        } else {
            SYSERR("JIT: unexpected exception type: %d from %d,%s\n", request->exception, pid, proc_get_path(pid,NULL));
        }

		reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg->msgh_bits), 0);
		reply.Head.msgh_size = sizeof(__Reply__mach_exception_raise_t);
		reply.Head.msgh_remote_port = msg->msgh_remote_port;
		reply.Head.msgh_local_port = MACH_PORT_NULL;
		reply.Head.msgh_id = msg->msgh_id + 0x64;

		mach_msg(&reply.Head, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	}
}


int proc_enable_jit(pid_t pid, bool resume)
{
	uint32_t csflags = 0;
	csops(pid, CS_OPS_STATUS, &csflags, sizeof(csflags));

    //but fork/vfork....
	// if((csflags & CS_DEBUGGED) != 0) {
	// 	SYSERR("JIT: process (%d,%s) has been debugged, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
	// 	return 0;
	// }

	if((csflags & CS_GET_TASK_ALLOW) == 0) {
		SYSERR("JIT: process (%d,%s) doesn't have CS_GET_TASK_ALLOW, csflags=0x%x", pid, proc_get_path(pid, NULL), csflags);
		return -1;
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

	int ret = -1;
	
	if(!resume)
	{
		kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
		if(kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
			SYSERR("JIT: task_for_pid(%d,task=%x) error: %x, %s", pid, task, kr, mach_error_string(kr));
			return -1;
		}

    	kr = task_get_exception_ports(task, EXC_MASK_SOFTWARE, saved_masks, &saved_exception_types_count, saved_ports, saved_behaviors, saved_flavors);
		if(kr != KERN_SUCCESS) {
			SYSERR("JIT: task_get_exception_ports(%d,task=%x) error: %x, %s", pid, task, kr, mach_error_string(kr));
			goto cleanup;
		}

        kr = task_set_exception_ports(task, EXC_MASK_SOFTWARE, exception_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
        if(kr != KERN_SUCCESS) {
			SYSERR("JIT: task_set_exception_ports(%d,task=%x) error: %x, %s", pid, task, kr, mach_error_string(kr));
			goto cleanup;
		}
	}

	ret = ptrace(PT_ATTACHEXC, pid, NULL, 0);
	if(ret != 0) {
		SYSERR("JIT: PT_ATTACHEXC(%d,%s) err = %d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
		goto cleanup;
	}

	//don't SIGCONT here, otherwise kernel may send exception msg to this process and the traced process keep waiting, kill(pid, SIGCONT);

	bool paused=false;
	for(int i=0; i<1000*50; i++)
    {
        ret = proc_paused(pid, &paused);
        SYSLOG("JIT: process paused=%d, %d", ret, paused);
        
        if(ret != 0) {
			goto cleanup;
		}
        
        if(paused) break;

		usleep(10);
	}

	if(!paused) {
		SYSERR("JIT:  wait process timeout: %d,%s", pid, proc_get_path(pid, NULL));
	}
	
    ret = ptrace(PT_DETACH, pid, NULL, resume ? 0 : SIGSTOP);
	if(ret != 0) {
		SYSERR("JIT: PT_DETACH(%d,%s) err = %d,%s", pid, proc_get_path(pid, NULL), errno, strerror(errno));
		goto cleanup;
	}

cleanup:

	for (uint32_t i = 0; i < saved_exception_types_count; ++i) {
		kern_return_t kr = task_set_exception_ports(task, saved_masks[i], saved_ports[i], saved_behaviors[i], saved_flavors[i]);
		if(kr != KERN_SUCCESS) {
			SYSERR("JIT: task_set_exception_ports[%d] error: %x, %s\n", i, kr, mach_error_string(kr));
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

	return ret;
}
