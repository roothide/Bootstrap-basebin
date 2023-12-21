
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <util.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

#include "common.h"

void forkfix(const char* tag, bool flag)
{
    // if(flag) {
    //     int count=0;
    //     thread_act_array_t list;
    //     assert(task_threads(mach_task_self(), &list, &count) == KERN_SUCCESS);
    //     for(int i=0; i<count; i++) {
    //         if(list[i] != mach_thread_self()) { //mach_port_deallocate
    //             assert(thread_suspend(list[i]) == KERN_SUCCESS);
    //         }
    //     }
    // }

    struct mach_header_64* header = _dyld_get_prog_image_header(); //_NSGetMachExecuteHeader()
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            if(strcmp(seg->segname, SEG_TEXT)==0)
            {
                //SYSLOG("%s[%d] segment: %s file=%llx:%llx vm=%p:%llx\n", tag, flag, seg->segname, seg->fileoff, seg->filesize, (void*)seg->vmaddr, seg->vmsize);

                //According to dyld, the __TEXT address is always equal to the header address

                //showvm(task, addr, seg->vmsize); 
                //mach_port_deallocate
                kern_return_t kr = vm_protect(task_self_trap(), (vm_address_t)header, seg->vmsize, false, flag ? VM_PROT_READ : VM_PROT_READ|VM_PROT_EXECUTE);
                assert(kr == KERN_SUCCESS);
                if(kr != KERN_SUCCESS) {
                    //fprintf(stderr, "[%d] %s[%d] vm_protect failed! %d,%s\n", getpid(), tag, flag,  kr, mach_error_string(kr));
                } else {
                    //fprintf(stderr, "[%d] %s[%d] vm_protect success @ %p,%llx\n", getpid(), tag, flag,  (void*)header, seg->vmsize);
                }

                //showvm(task, addr, seg->vmsize);

                break;
            }
        }
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    // if(!flag) {
    //     int count=0;
    //     thread_act_array_t list;
    //     assert(task_threads(mach_task_self(), &list, &count) == KERN_SUCCESS);
    //     for(int i=0; i<count; i++) {
    //         if(list[i] != mach_thread_self()) { //mach_port_deallocate
    //             assert(thread_resume(list[i]) == KERN_SUCCESS);
    //         }
    //     }
    // }   
}



extern pid_t __fork(void);
extern pid_t __vfork(void);

static void (**_libSystem_atfork_prepare)(void) = 0;
static void (**_libSystem_atfork_parent)(void) = 0;
static void (**_libSystem_atfork_child)(void) = 0;
static void (**_libSystem_atfork_prepare_v2)(unsigned int flags, ...) = 0;
static void (**_libSystem_atfork_parent_v2)(unsigned int flags, ...) = 0;
static void (**_libSystem_atfork_child_v2)(unsigned int flags, ...) = 0;

#define RESOVLE_ATFORK(n)  {\
*(void**)&n = DobbySymbolResolver("/usr/lib/system/libsystem_c.dylib", #n);\
  SYSLOG("forkfunc %s = %p", #n, n);\
  }

#include "dobby.h"
static void 
//__attribute__((__constructor__)) 
atforkinit()
{
    RESOVLE_ATFORK(_libSystem_atfork_prepare);
    RESOVLE_ATFORK(_libSystem_atfork_parent);
    RESOVLE_ATFORK(_libSystem_atfork_child);
    RESOVLE_ATFORK(_libSystem_atfork_prepare_v2);
    RESOVLE_ATFORK(_libSystem_atfork_parent_v2);
    RESOVLE_ATFORK(_libSystem_atfork_child_v2);
}

//redefine for pointers
#define _libSystem_atfork_prepare		(*_libSystem_atfork_prepare)
#define _libSystem_atfork_parent  		(*_libSystem_atfork_parent)
#define _libSystem_atfork_child  		(*_libSystem_atfork_child)
#define _libSystem_atfork_prepare_v2  	(*_libSystem_atfork_prepare_v2)
#define _libSystem_atfork_parent_v2  	(*_libSystem_atfork_parent_v2)
#define _libSystem_atfork_child_v2  	(*_libSystem_atfork_child_v2)

#include <signal.h>
struct sigaction fork_oldact = {0};
void forksig(int signo, siginfo_t *info, void *context)
{
    fprintf(stderr, "%d forksig %d %p\n", getpid(), info->si_pid, fork_oldact.sa_sigaction);

    forkfix("sig", false);

    if(fork_oldact.sa_sigaction) {
        fork_oldact.sa_sigaction(signo, info, context);
    }
}

#define LIBSYSTEM_ATFORK_HANDLERS_ONLY_FLAG 1

static inline __attribute__((always_inline))
pid_t
_do_fork(bool libsystem_atfork_handlers_only)
{
	static int atforkinited=0;
	if(atforkinited++==0) atforkinit();

	int ret;

	int flags = libsystem_atfork_handlers_only ? LIBSYSTEM_ATFORK_HANDLERS_ONLY_FLAG : 0;

	if (_libSystem_atfork_prepare_v2) {
		_libSystem_atfork_prepare_v2(flags);
	} else {
		_libSystem_atfork_prepare();
	}
	// Reader beware: this __fork() call is yet another wrapper around the actual syscall
	// and lives inside libsyscall. The fork syscall needs some cuddling by asm before it's
	// allowed to see the big wide C world.


	// struct sigaction act = {0};
    // struct sigaction oldact = {0};

	// act.sa_flags = SA_ONSTACK|SA_NODEFER|SA_SIGINFO;
    // act.sa_sigaction = forksig;
	// sigfillset(&act.sa_mask);

	// sigaction(SIGCHLD, &act, &oldact);
    // if(oldact.sa_sigaction != forksig) fork_oldact = oldact;
    // fprintf(stderr, "oldact=%x %x %p\n", oldact.sa_flags, oldact.sa_mask, oldact.sa_sigaction);

    // fprintf(stderr, "do fork %d\n", getpid());

    sigset_t newmask, oldmask;
    sigfillset(&newmask);
    sigprocmask(SIG_BLOCK, &newmask, &oldmask);

    forkfix(libsystem_atfork_handlers_only?"vfork":"fork", true);
	pid_t pid = ret = __fork();
    forkfix(libsystem_atfork_handlers_only?"vfork":"fork", false);

    sigprocmask(SIG_SETMASK, &oldmask, NULL);

	if (-1 == ret)
	{
		// __fork already set errno for us
		if (_libSystem_atfork_parent_v2) {
			_libSystem_atfork_parent_v2(flags);
		} else {
			_libSystem_atfork_parent();
		}
		return ret;
	}

	if (0 == ret)
	{
		// We're the child in this part.
		if (_libSystem_atfork_child_v2) {
			_libSystem_atfork_child_v2(flags);
		} else {
			_libSystem_atfork_child();
		}
		return 0;
	}

	if (_libSystem_atfork_parent_v2) {
		_libSystem_atfork_parent_v2(flags);
	} else {
		_libSystem_atfork_parent();
	}
	return ret;
}

pid_t
_fork(void)
{
	return _do_fork(false);
}

pid_t
_vfork(void)
{
	// vfork() is now just fork().
	// Skip the API pthread_atfork handlers, but do call our own
	// Libsystem_atfork handlers. People are abusing vfork in ways where
	// it matters, e.g. tcsh does all kinds of stuff after the vfork. Sigh.
	return _do_fork(true);
}




int
_forkpty(int *aprimary, char *name, struct termios *termp, struct winsize *winp)
{
	int primary, replica, pid;

	if (openpty(&primary, &replica, name, termp, winp) == -1)
		return (-1);
	switch (pid = fork()) {
	case -1:
		return (-1);
	case 0:
		/* 
		 * child
		 */
		(void) close(primary);
		/*
		 * 4300297: login_tty() may fail to set the controlling tty.
		 * Since we have already forked, the best we can do is to 
		 * dup the replica as if login_tty() succeeded.
		 */
		if (login_tty(replica) < 0) {
			syslog(LOG_ERR, "forkpty: login_tty could't make controlling tty");
			(void) dup2(replica, 0);
			(void) dup2(replica, 1);
			(void) dup2(replica, 2);
			if (replica > 2)
				(void) close(replica);
		}
		return (0);
	}
	/*
	 * parent
	 */
	*aprimary = primary;
	(void) close(replica);
	return (pid);
}


#define _dup2 dup2
#define _open open
#define _close close
#define _sigaction sigaction
#include <paths.h>
#include <fcntl.h>
#ifndef VARIANT_PRE1050
#include <mach/mach_init.h>
#include <bootstrap.h>
static void
move_to_root_bootstrap(void)
{
	mach_port_t parent_port = 0;
	mach_port_t previous_port = 0;

	do {
		if (previous_port) {
			mach_port_deallocate(mach_task_self(), previous_port);
			previous_port = parent_port;
		} else {
			previous_port = bootstrap_port;
		}

		if (bootstrap_parent(previous_port, &parent_port) != 0) {
			return;
		}
	} while (parent_port != previous_port);

	task_set_bootstrap_port(mach_task_self(), parent_port);
	bootstrap_port = parent_port;
}
#endif /* !VARIANT_PRE1050 */

int daemon(int, int) __DARWIN_1050(daemon);

int
_daemon(nochdir, noclose)
	int nochdir, noclose;
{
	struct sigaction osa, sa;
	int fd;
	pid_t newgrp;
	int oerrno;
	int osa_ok;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = _sigaction(SIGHUP, &sa, &osa);
#ifndef VARIANT_PRE1050
	move_to_root_bootstrap();
#endif /* !VARIANT_PRE1050 */
	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	newgrp = setsid();
	oerrno = errno;
	if (osa_ok != -1)
		_sigaction(SIGHUP, &osa, NULL);

	if (newgrp == -1) {
		errno = oerrno;
		return (-1);
	}

	if (!nochdir)
		(void)chdir("/");

	if (!noclose && (fd = _open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(void)_dup2(fd, STDIN_FILENO);
		(void)_dup2(fd, STDOUT_FILENO);
		(void)_dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)_close(fd);
	}
	return (0);
}
