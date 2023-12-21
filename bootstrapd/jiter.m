
#include <Foundation/Foundation.h>
#import <pthread/stack_np.h>
#import <pthread/pthread.h>
#import <mach/exception_types.h>
#import <mach/mach.h>
#include <signal.h>
#include <pthread.h>


// pthread_t gExceptionThread = 0;
// mach_port_t gExceptionPort = MACH_PORT_NULL;

// #define EXC_MASK_CRASH_RELATED (EXC_MASK_BAD_ACCESS | \
//         EXC_MASK_BAD_INSTRUCTION |              \
//         EXC_MASK_ARITHMETIC |                  \
//         EXC_MASK_EMULATION |                  \
//         EXC_MASK_SOFTWARE |                      \
//         EXC_MASK_BREAKPOINT)

// typedef int                             exception_type_t;
// typedef integer_t                       exception_data_type_t;

// typedef struct {
//     mach_msg_header_t header;
//     mach_msg_body_t msgh_body;
//     mach_msg_port_descriptor_t thread;
//     mach_msg_port_descriptor_t task;
//     int unused1;
//     exception_type_t exception;
//     exception_data_type_t code;
//     int unused2;
//     int subcode;
//     NDR_record_t ndr;
// } exception_raise_request; // the bits we need at least

// typedef struct {
//     mach_msg_header_t header;
//     NDR_record_t ndr;
//     kern_return_t retcode;
// } exception_raise_reply;

// typedef struct {
//     mach_msg_header_t header;
//     NDR_record_t ndr;
//     kern_return_t retcode;
//     int flavor;
//     mach_msg_type_number_t new_stateCnt;
//     natural_t new_state[614];
// } exception_raise_state_reply;


// void *crashreporter_listen(void *arg)
// {
//     while (true) {
//         mach_msg_header_t msg={0};
//         msg.msgh_local_port = gExceptionPort;
//         msg.msgh_size = 1024;
//         mach_msg_receive(&msg);

//         exception_raise_request *request = (exception_raise_request*)&msg;

// //        pthread_t pthread = pthread_from_mach_thread_np(request->thread.name);

//         mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
//         arm_thread_state64_t threadState;
//         thread_get_state(request->thread.name, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);

//         arm_exception_state64_t exceptionState;
//         mach_msg_type_number_t exceptionStateCount = ARM_EXCEPTION_STATE64_COUNT;
//         thread_get_state(request->thread.name, ARM_EXCEPTION_STATE64, (thread_state_t)&exceptionState, &exceptionStateCount);
        
//         uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(threadState);

//         pid_t pid=0;
//         pid_for_task(request->task.name, &pid);
//         NSLog(@"pid=%d exception: %d,%d,%d thread=%x pc=%p", pid, request->exception, request->code, request->subcode, request->thread.name, (void*)pc);
        
//         exception_raise_reply reply={0};
//         reply.ndr = request->ndr;
//         reply.retcode = KERN_SUCCESS;

//         reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.msgh_bits), 0);
//         reply.header.msgh_size = sizeof(exception_raise_reply);
//         reply.header.msgh_remote_port = msg.msgh_remote_port;
//         reply.header.msgh_local_port = MACH_PORT_NULL;
//         reply.header.msgh_id = msg.msgh_id + 0x64;

//         mach_msg(&reply.header, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, reply.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
//     }
// }



// static void __attribute__((__constructor__)) init()
// {
//     mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gExceptionPort);
//     mach_port_insert_right(mach_task_self_, gExceptionPort, gExceptionPort, MACH_MSG_TYPE_MAKE_SEND);
//     pthread_create(&gExceptionThread, NULL, crashreporter_listen, "crashreporter");
// }


#include "libproc.h"
#include "libproc_private.h"


/* Status values. */
#define SIDL    1               /* Process being created by fork. */
#define SRUN    2               /* Currently runnable. */
#define SSLEEP  3               /* Sleeping on an address. */
#define SSTOP   4               /* Process debugging or suspension. */
#define SZOMB   5               /* Awaiting collection by parent. */

int proc_paused(pid_t pid, bool* paused)
{
	*paused = false;

	struct proc_bsdinfo procInfo={0};
	int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
	if(ret != sizeof(procInfo)) {
		NSLog(@"bsdinfo failed, %d,%s\n", errno, strerror(errno));
		return -1;
	}

	if(procInfo.pbi_status == SSTOP)
	{
		NSLog(@"%d pstat=%x flag=%x xstat=%x\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus);
		*paused = true;
	}
	else if(procInfo.pbi_status != SRUN) {
		NSLog(@"unexcept %d pstat=%x\n", ret, procInfo.pbi_status);
		return -1;
	}

	return 0;
}


#define PT_DETACH       11      /* stop tracing a process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */
int     ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

#include <signal.h>

int enableJIT(pid_t pid)
{
	int ret = ptrace(PT_ATTACHEXC, pid, NULL, 0);
	NSLog(@"attach=%d", ret);
	if(ret != 0) return ret;

	//don't SIGCONT here, otherwise kernel may send exception msg to this process and the traced process keep waiting, kill(pid, SIGCONT);

	for(int i=0; i<1000*50; i++)
    {
        bool paused=false;
        ret = proc_paused(pid, &paused);
        NSLog(@"paused=%d, %d", ret, paused);
        
        if(ret != 0) return ret;
        
        if(paused) break;

		usleep(10);
	}
	
    ret = ptrace(PT_DETACH, pid, NULL, 0);
    NSLog(@"detach=%d, %s", ret, strerror(errno));
        
	return ret;
}
