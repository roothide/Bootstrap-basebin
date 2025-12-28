
#include <Foundation/Foundation.h>
#include <signal.h>
#include <pthread.h>
#include "common.h"

#define PT_DETACH       11      /* stop tracing a process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */
int     ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

#include <signal.h>

int enableJIT(pid_t pid)
{
	int ret = ptrace(PT_ATTACHEXC, pid, NULL, 0);
	SYSLOG("attach=%d", ret);
	if(ret != 0) return ret;

	//don't SIGCONT here, otherwise kernel may send exception msg to this process and the traced process keep waiting, kill(pid, SIGCONT);

	bool paused=false;
	for(int i=0; i<1000*50; i++)
    {
        ret = proc_paused(pid, &paused);
        SYSLOG("paused=%d, %d", ret, paused);
        
        if(ret != 0) return ret;
        
        if(paused) break;

		usleep(10);
	}

	if(!paused) {
		SYSLOG("*** ptrace: wait process timeout");
	}
	
    ret = ptrace(PT_DETACH, pid, NULL, 0);
    SYSLOG("detach=%d, %s", ret, ret==0?"":strerror(errno));

	return ret;
}
