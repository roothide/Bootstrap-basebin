
#include <Foundation/Foundation.h>
#include <signal.h>
#include <pthread.h>
#include "common.h"
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
		SYSLOG("bsdinfo failed, %d,%s\n", errno, strerror(errno));
		return -1;
	}

	if(procInfo.pbi_status == SSTOP)
	{
		SYSLOG("%d pstat=%x flag=%x xstat=%x\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus);
		*paused = true;
	}
	else if(procInfo.pbi_status != SRUN) {
		SYSLOG("unexcept %d pstat=%x\n", ret, procInfo.pbi_status);
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
	SYSLOG("attach=%d", ret);
	if(ret != 0) return ret;

	//don't SIGCONT here, otherwise kernel may send exception msg to this process and the traced process keep waiting, kill(pid, SIGCONT);

	for(int i=0; i<1000*50; i++)
    {
        bool paused=false;
        ret = proc_paused(pid, &paused);
        SYSLOG("paused=%d, %d", ret, paused);
        
        if(ret != 0) return ret;
        
        if(paused) break;

		usleep(10);
	}
	
    ret = ptrace(PT_DETACH, pid, NULL, 0);
    SYSLOG("detach=%d, %s", ret, ret==0?"":strerror(errno));
        
	return ret;
}
