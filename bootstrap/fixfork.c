
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <util.h>
#include <signal.h>
#import <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <CoreFoundation/CoreFoundation.h>

#include "common.h"
#include "libbsd.h"
#include "ipc.h"

//#define FORK_DEBUG

#ifndef CPUFAMILY_ARM_PCORE_ECORE_COLL
#define CPUFAMILY_ARM_PCORE_ECORE_COLL 0x2876f5b5
#endif

#define printf_putchar(x) do{int l=strlen(buffer);if(l<bufsize)buffer[l]=x;}while(0)

int _vsnprintf(char* buffer, int bufsize, const char * __restrict format, va_list vl) {
    bool special = false;
    
    memset(buffer,0,bufsize);
    
    while (*format) {
        if (special) {
            switch (*format) {
                case 'x':
                case 'p': {
                    // Pointer
                    printf_putchar('0');
                    printf_putchar('x');
                    
                    uintptr_t ptr = va_arg(vl, uintptr_t);
                    bool didWrite = false;
                    for (int i = 7; i >= 0; i--) {
                        uint8_t cur = (ptr >> (i * 8)) & 0xFF;
                        char first = cur >> 4;
                        if (first >= 0 && first <= 9) {
                            first = first + '0';
                        } else {
                            first = (first - 0xA) + 'A';
                        }
                        
                        char second = cur & 0xF;
                        if (second >= 0 && second <= 9) {
                            second = second + '0';
                        } else {
                            second = (second - 0xA) + 'A';
                        }
                        
                        if (didWrite || cur) {
                            if (didWrite || first != '0') {
                                printf_putchar(first);
                            }
                            
                            printf_putchar(second);
                            didWrite = true;
                        }
                    }
                    
                    if (!didWrite) {
                        printf_putchar('0');
                    }
                    break;
                }

                case 'd': {
                    int i = va_arg(vl, int);
                    #define INT_DIGITS 32
                    char buf[INT_DIGITS + 2]={0};
                    char *p = buf + INT_DIGITS + 1;    /* points to terminating '\0' */
                    if (i >= 0) {
                        do {
                        *--p = '0' + (i % 10);
                        i /= 10;
                        } while (i != 0);
                    }
                    else {            /* i < 0 */
                        do {
                        *--p = '0' - (i % 10);
                        i /= 10;
                        } while (i != 0);
                        *--p = '-';
                    }
                    for(int i=0; i<strlen(p); i++) {
                        printf_putchar(p[i]);
                    }
                    break;
                }
                    
                case 'u': {
                    unsigned int i = va_arg(vl, unsigned int);
                    #define INT_DIGITS 32
                    char buf[INT_DIGITS + 2]={0};
                    char *p = buf + INT_DIGITS + 1;    /* points to terminating '\0' */
                    do {
                      *--p = '0' + (i % 10);
                      i /= 10;
                    } while (i != 0);
                    for(int i=0; i<strlen(p); i++) {
                        printf_putchar(p[i]);
                    }
                    break;
                }
                    
                case 's': {
                    const char *str = va_arg(vl, const char*);
                    if (str == NULL) {
                        str = "<NULL>";
                    }
                    
                    while (*str) {
                        printf_putchar(*str++);
                    }
                    break;
                }
                    
                case 'c':
                    printf_putchar(va_arg(vl, int));
                    break;
                    
                case 'l':
                    // Prefix, ignore
                    format++;
                    continue;
                    
                case '%':
                    printf_putchar(*format);
                    break;
                    
                default:
                    printf_putchar('%');
                    printf_putchar(*format);
                    break;
            }
            
            special = false;
        } else {
            if (*format == '%') {
                special = true;
            } else {
                printf_putchar(*format);
            }
        }
        
        format++;
    }
    
    return 0; // Not up to spec, but who uses the return value of (v)printf anyway?
}

int _snprintf(char* buffer, int bufsize, const char * __restrict format, ...) {
    va_list vl;
    va_start(vl, format);
    
    int res = _vsnprintf(buffer, bufsize, format, vl);
    
    va_end(vl);
    
    return res;
}

#ifdef FORK_DEBUG
#define forklog(...)	do {\
char buf[1024];\
_snprintf(buf,sizeof(buf),__VA_ARGS__);\
write(STDERR_FILENO,buf,strlen(buf));\
write(STDERR_FILENO,"\n",1);\
fsync(STDERR_FILENO);\
} while(0)
#else
#define forklog(...)
#endif



bool forkfix_method_2=false;

pid_t ffsys_fork(void);
pid_t ffsys_getpid(void);
ssize_t ffsys_read(int fildes, void *buf, size_t nbyte);
ssize_t ffsys_write(int fildes, const void *buf, size_t nbyte);
int ffsys_close(int fildes);

bool* _DisableInitializeForkSafety = NULL;
static void (**_libSystem_atfork_prepare)(void) = 0;
static void (**_libSystem_atfork_parent)(void) = 0;
static void (**_libSystem_atfork_child)(void) = 0;
static void (**_libSystem_atfork_prepare_v2)(unsigned int flags, ...) = 0;
static void (**_libSystem_atfork_parent_v2)(unsigned int flags, ...) = 0;
static void (**_libSystem_atfork_child_v2)(unsigned int flags, ...) = 0;

#define RESOVLE_ATFORK(n)  {\
*(void**)&n = DobbySymbolResolver("/usr/lib/system/libsystem_c.dylib", #n);\
    forklog("forkfunc %s = %p:%p", #n, n, n?*n:NULL);\
  }

#include "dobby.h"
static void 
//__attribute__((__constructor__)) 
atforkinit()
{
    if((int)kCFCoreFoundationVersionNumber >= 2000) 
    {
        cpu_subtype_t cpuFamily = 0;
        size_t cpuFamilySize = sizeof(cpuFamily);
        sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);

        struct utsname systemInfo;
        uname(&systemInfo);

        if (strncmp(systemInfo.machine, "iPhone", 6)==0
         && (cpuFamily==CPUFAMILY_ARM_BLIZZARD_AVALANCHE
         || cpuFamily==CPUFAMILY_ARM_EVEREST_SAWTOOTH
          || cpuFamily==CPUFAMILY_ARM_PCORE_ECORE_COLL )) {
            forkfix_method_2 = true;
        }

        //ipad mini6, A15 not M2
        if ((strcmp(systemInfo.machine, "iPad14,1")==0 || strcmp(systemInfo.machine, "iPad14,2")==0) 
        && (cpuFamily==CPUFAMILY_ARM_BLIZZARD_AVALANCHE)) {
            forkfix_method_2 = true;
        }
    }

    static_assert(sizeof(bool) == 1, "bool size mismatch");
    _DisableInitializeForkSafety = (bool*)DobbySymbolResolver("/usr/lib/libobjc.A.dylib", "DisableInitializeForkSafety");
    
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



void showvm(task_port_t task, uint64_t start, uint64_t size)
{
    vm_size_t region_size=0;
    vm_address_t region_base = start;
    natural_t depth = 1;
    
    while((region_base+region_size) < (start+size)) {
        region_base += region_size;
        
        struct vm_region_submap_info_64 info={0};
        mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        
        kern_return_t kr = vm_region_recurse_64(task, &region_base, &region_size,
                                          &depth, (vm_region_info_t)&info, &info_cnt);
        
        if(kr != KERN_SUCCESS) {
            forklog("[%d] vm_region failed on %p, %x:%s", getpid(), (void*)region_base, kr, mach_error_string(kr));
            break;
        }
        
        forklog("[%d] found region %p %lx [%d/%d], %x/%x, %d\n", getpid(), (void*)region_base, region_size, info.is_submap, depth, info.protection, info.max_protection, info.user_tag);

        if(info.is_submap) {
            region_size=0;
            depth++;
            continue;
        }
        
    } 
}

__attribute__((noinline, naked)) volatile kern_return_t _mach_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
    __asm("mov x16, #0xFFFFFFFFFFFFFFF2");
    __asm("svc 0x80");
    __asm("ret");
}

__attribute__((noinline, naked)) volatile mach_port_name_t _task_self_trap(void)
{
    __asm("mov x16, #0xFFFFFFFFFFFFFFE4");
    __asm("svc 0x80");
    __asm("ret");
}

__attribute__((noinline, naked)) int _sigprocmask(int how, const sigset_t *nsm, sigset_t *osm)
{
    __asm("mov x16, #0x30");
    __asm("svc 0x80");
    __asm("ret");
}

__attribute__((noinline, naked)) int _sigaction(int sig, const struct sigaction * __restrict nsv, struct sigaction * __restrict osv)
{
    __asm("mov x16, #0x2E");
    __asm("svc 0x80");
    __asm("ret");
}

__attribute__((noinline, naked)) int syscall__abort_with_payload(uint32_t reason_namespace, uint64_t reason_code,
				void *payload, uint32_t payload_size, const char *reason_string, uint64_t reason_flags)
{
    __asm("mov x16, #0x209");
    __asm("svc 0x80");
    __asm("ret");
}

__attribute__((noinline, naked)) int syscall__terminate_with_payload(int pid, uint32_t reason_namespace, uint64_t reason_code,
				void *payload, uint32_t payload_size, const char *reason_string, uint64_t reason_flags)
{
    __asm("mov x16, #0x208");
    __asm("svc 0x80");
    __asm("ret");
}

void fork_abort(const char* reason) {

    struct sigaction act={0};
    act.sa_handler = SIG_DFL;
    _sigaction(SIGABRT, &act, NULL);

    sigset_t mask = __sigbits(SIGABRT);
    _sigprocmask(SIG_UNBLOCK, &mask, NULL);

    syscall__abort_with_payload(OS_REASON_DYLD, DYLD_EXIT_REASON_OTHER, NULL, 0, reason, 0);
    syscall__terminate_with_payload(ffsys_getpid(), OS_REASON_DYLD, DYLD_EXIT_REASON_OTHER, NULL, 0, reason, 0x200);
    // should never return
}

#define fork_assert(e)	(__builtin_expect(!(e), 0) ? fork_abort(#e) : (void)0)

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

int _strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}

void forkfix(const char* tag, bool flag, bool child)
{
	kern_return_t kr = -1;
	mach_port_t task = _task_self_trap();//mach_port_deallocate for task_self_trap()

    // if(flag) {
    //     int count=0;
    //     thread_act_array_t list;
    //     ASSERT(task_threads(task, &list, &count) == KERN_SUCCESS);
    //     for(int i=0; i<count; i++) {
    //         if(list[i] != mach_thread_self()) { //mach_port_deallocate
    //             ASSERT(thread_suspend(list[i]) == KERN_SUCCESS);
    //         }
    //     }
    // }


    static struct mach_header_64* header = NULL; //save the header for child on parent
    if(!header) header = _dyld_get_prog_image_header(); //_NSGetMachExecuteHeader()
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            if(_strcmp(seg->segname, SEG_TEXT)==0)
            {
                forklog("%s-%d segment: %s file=%llx:%llx vm=%p:%llx\n", tag, flag, seg->segname, seg->fileoff, seg->filesize, (void*)seg->vmaddr, seg->vmsize);

                //According to dyld, the __TEXT address is always equal to the header address

#ifdef FORK_DEBUG
                showvm(task, (uint64_t)header, seg->vmsize);
#endif
                if(!forkfix_method_2)
                {
                    kr = _mach_vm_protect(task, (vm_address_t)header, seg->vmsize, false, flag ? VM_PROT_READ : VM_PROT_READ|VM_PROT_EXECUTE);
                    forklog("[%d] %s vm_protect.%d %d,%s\n", getpid(), tag, flag,  kr, mach_error_string(kr));
                    fork_assert(kr == KERN_SUCCESS);
                }

				// ASSERT(*(int*)textaddr);

#ifdef FORK_DEBUG
                // showvm(task, (uint64_t)header, seg->vmsize); //stack overflow by mig_get_reply_port infinite reucrsion on child process
#endif

                break;
            }
        }
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    // if(!flag) {
    //     int count=0;
    //     thread_act_array_t list;
    //     ASSERT(task_threads(task, &list, &count) == KERN_SUCCESS);
    //     for(int i=0; i<count; i++) {
    //         if(list[i] != mach_thread_self()) { //mach_port_deallocate
    //             ASSERT(thread_resume(list[i]) == KERN_SUCCESS);
    //         }
    //     }
    // }   
}

// struct sigaction fork_oldact = {0};
// void forksig(int signo, siginfo_t *info, void *context)
// {
//     forklog("%d forksig %d %p\n", getpid(), info->si_pid, fork_oldact.sa_sigaction);

//     forkfix("sig", false);

//     if(fork_oldact.sa_sigaction) {
//         fork_oldact.sa_sigaction(signo, info, context);
//     }
// }


extern void _malloc_fork_prepare(void);
extern void _malloc_fork_parent(void);
extern void xpc_atfork_prepare(void);
extern void xpc_atfork_parent(void);
extern void dispatch_atfork_prepare(void);
extern void dispatch_atfork_parent(void);

int childToParentPipe[2];
int parentToChildPipe[2];
static void openPipes(void)
{
	if (pipe(parentToChildPipe) < 0 || pipe(childToParentPipe) < 0) {
		fork_abort("openPipes");
	}
}
static void closePipes(void)
{
	if (ffsys_close(parentToChildPipe[0]) != 0 || ffsys_close(parentToChildPipe[1]) != 0 || ffsys_close(childToParentPipe[0]) != 0 || ffsys_close(childToParentPipe[1]) != 0) {
		fork_abort("closePipes");
	}
}

void child_fixup(void)
{
	// Tell parent we are waiting for fixup now
	char msg = ' ';
	ffsys_write(childToParentPipe[1], &msg, sizeof(msg));

	// Wait until parent completes fixup
	while((ffsys_read(parentToChildPipe[0], &msg, sizeof(msg))<0) && errno==EINTR){}; //may be interrupted by ptrace

}

void parent_fixup(pid_t childPid)
{
	// Reenable some system functionality that XPC is dependent on and XPC itself
	// (Normally unavailable during __fork)
	_malloc_fork_parent();
	dispatch_atfork_parent();
	xpc_atfork_parent();

	// Wait until the child is ready and waiting
	char msg = ' ';
	read(childToParentPipe[0], &msg, sizeof(msg));
	
	//disable ipc log during fork()
	bool ipclog_status = set_ipclog_enabled(false);
	if(bsd_enableJIT2(childPid) != 0) {
        kill(childPid, SIGKILL);
    }
    set_ipclog_enabled(ipclog_status);

	// Tell child we are done, this will make it resume
	write(parentToChildPipe[1], &msg, sizeof(msg));

	// Disable system functionality related to XPC again
	_malloc_fork_prepare();
	dispatch_atfork_prepare();
	xpc_atfork_prepare();
}

pid_t __fork1(void)
{
	openPipes();

	pid_t pid = ffsys_fork();
	if (pid < 0) {
		closePipes();
		return pid;
	}

	if (pid == 0) {
		child_fixup();
	}
	else {
		parent_fixup(pid);
	}

	closePipes();
	return pid;
}

#define LIBSYSTEM_ATFORK_HANDLERS_ONLY_FLAG 1

#include <dlfcn.h>
extern void* _dyld_get_shared_cache_range(size_t* length);

static inline __attribute__((always_inline))
pid_t
_do_fork(bool libsystem_atfork_handlers_only)
{
	// ASSERT(requireJIT()==0);

	static int atforkinited=0;
	if(atforkinited++==0) atforkinit();

	forklog("atfork inited");

    //make sure it's not reparented to launchd (cause we cannot detect reparent from user land)
    if(forkfix_method_2 && get_real_ppid()==1 && kill(getpgrp(), 0)==0 && is_app_coalition()) {
        //prevent sptm panic
        return -1;
    }

    size_t dsc_length=0;
    void* dsc_start = _dyld_get_shared_cache_range(&dsc_length);

    natural_t depth = 1;
    vm_size_t region_size = 0;
    vm_address_t region_base = 0;
    
    while(true)
    {     
        struct vm_region_submap_info_64 info={0};
        mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region_base, &region_size,
                                            &depth, (vm_region_info_t)&info, &info_cnt);
        if(kr != KERN_SUCCESS) {
            break;
        }

        if(info.is_submap != 0) {
            depth++;
        }
        else 
        {
            if ((info.protection & VM_PROT_EXECUTE) != 0) {
                if (info.share_mode == SM_PRIVATE) {
                    if((uint64_t)region_base >= (uint64_t)dsc_start
                     && (uint64_t)region_base < ((uint64_t)dsc_start+dsc_length))
                    {
                        return -1;
                    }
                }
            }

            region_base += region_size;
        }
    }


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

	// act.sa_flags = SA_ONSTACK|SA_SIGINFO;
    // act.sa_sigaction = forksig;
	// sigfillset(&act.sa_mask);

	// sigaction(SIGCHLD, &act, &oldact);
    // if(oldact.sa_sigaction != forksig) fork_oldact = oldact;
    // forklog("oldact=%x %x %p\n", oldact.sa_flags, oldact.sa_mask, oldact.sa_sigaction);

	// for(int i=0; i<999; i++) sigignore(i);

    forklog("do fork %d\n", getpid());

    sigset_t newmask, oldmask;
    sigfillset(&newmask);
    sigprocmask(SIG_BLOCK, &newmask, &oldmask);

    forklog("fork fix %d\n", getpid());
    forkfix(libsystem_atfork_handlers_only?"vfork":"fork", true, false);

	pid_t pid = ret = __fork1();
    forklog("forked %d\n", pid);

    forkfix(libsystem_atfork_handlers_only?"vfork":"fork", false, pid==0);
    forklog("fork fixed %d\n", getpid());

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
        bool _old=*_DisableInitializeForkSafety;
        *_DisableInitializeForkSafety = true;

		// We're the child in this part.
		if (_libSystem_atfork_child_v2) {
			_libSystem_atfork_child_v2(flags);
		} else {
			_libSystem_atfork_child();
		}

        *_DisableInitializeForkSafety = _old;
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
	switch (pid = _fork()) {
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
_daemon(int nochdir, int noclose)
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
	switch (_fork()) {
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
