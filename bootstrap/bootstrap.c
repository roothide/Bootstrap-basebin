#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <util.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <spawn.h>
#include <paths.h>
#include <dlfcn.h>
#include <assert.h>
#include <roothide.h>
#include "common.h"
#include "fishhook.h"
#include "sandbox.h"
#include "../bootstrapd/libbsd.h"


#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
			__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

pid_t fork_hook()
{
    pid_t _fork();
    return _fork();
}

pid_t vfork_hook()
{
    pid_t _vfork();
    return _vfork();
}

pid_t forkpty_hook(int *amaster, char *name, struct termios *termp, struct winsize *winp)
{
    pid_t _forkpty(int*,char*,struct termios*,struct winsize*);
    return _forkpty(amaster,name,termp,winp);
}

int daemon_hook(int __nochdir, int __noclose)
{
    int _daemon(int,int);
    return _daemon(__nochdir, __noclose);
}



int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));

int posix_spawnp_hook(pid_t *restrict pid, const char *restrict file,
					   const posix_spawn_file_actions_t *restrict file_actions,
					    posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	return resolvePath(file, NULL, ^int(char *path) {
		return posix_spawn_hook(pid, path, file_actions, attrp, argv, envp);
	});
}

int execve_hook(const char *path, char *const argv[], char *const envp[])
{
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int result = posix_spawn_hook(NULL, path, NULL, &attr, argv, envp);
	if (attr) {
		posix_spawnattr_destroy(&attr);
	}

	if(result != 0) { // posix_spawn will return errno and restore errno if it fails
		errno = result; // so we need to set errno by ourself
		return -1;
	}

	return result;
}

int execle_hook(const char *path, const char *arg0, ... /*, (char *)0, char *const envp[] */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char *); arg != NULL; arg = va_arg(args_copy, char *)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	char *nullChar = va_arg(args, char*);

	char **envp = va_arg(args, char**);
	return execve_hook(path, argv, envp);
}

int execlp_hook(const char *file, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char **argv = malloc((arg_count+1) * sizeof(char *));
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	int r = resolvePath(file, NULL, ^int(char *path) {
		return execve_hook(path, argv, environ);
	});

	free(argv);

	return r;
}

int execl_hook(const char *path, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	return execve_hook(path, argv, environ);
}

int execv_hook(const char *path, char *const argv[])
{
	return execve_hook(path, argv, environ);
}

int execvP_hook(const char *file, const char *search_path, char *const argv[])
{
	__block bool execve_failed = false;
	int err = resolvePath(file, search_path, ^int(char *path) {
		(void)execve_hook(path, argv, environ);
		execve_failed = true;
		return 0;
	});
	if (!execve_failed) {
		errno = err;
	}
	return -1;
}

int execvp_hook(const char *name, char * const *argv)
{
	const char *path;
	/* Get the path we're searching. */
	if ((path = getenv("PATH")) == NULL)
		path = _PATH_DEFPATH;
	return execvP_hook(name, path, argv);
}



DYLD_INTERPOSE(posix_spawn_hook, posix_spawn)
DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp)
DYLD_INTERPOSE(execve_hook, execve)
DYLD_INTERPOSE(execle_hook, execle)
DYLD_INTERPOSE(execlp_hook, execlp)
DYLD_INTERPOSE(execv_hook, execv)
DYLD_INTERPOSE(execl_hook, execl)
DYLD_INTERPOSE(execvp_hook, execvp)
DYLD_INTERPOSE(execvP_hook, execvP)
DYLD_INTERPOSE(fork_hook, fork)
DYLD_INTERPOSE(vfork_hook, vfork)
DYLD_INTERPOSE(forkpty_hook, forkpty)
DYLD_INTERPOSE(daemon_hook, daemon)

//dopamine interface
EXPORT int jbdswDebugMe()
{
	static int inited = 0;
	if(inited++) return 0;

	return bsd_enableJIT();
}

bool checkpatchedexe() {
	char executablePath[PATH_MAX]={0};
	uint32_t bufsize=sizeof(executablePath);
	assert(_NSGetExecutablePath(executablePath, &bufsize) == 0);
	
	char patcher[PATH_MAX];
	snprintf(patcher, sizeof(patcher), "%s.roothidepatch", executablePath);
	if(access(patcher, F_OK)==0) 
		return false;

	return true;
}

// const char* bootstrapath=NULL;
static void __attribute__((__constructor__)) bootstrap()
{
    SYSLOG("bootstrap....%s\n", getprogname());

	// struct dl_info di={0};
    // dladdr((void*)bootstrap, &di);
	// bootstrapath = strdup(di.dli_fname);

    const char* preload = getenv("DYLD_INSERT_LIBRARIES");
    if(!preload || !strstr(preload,"/basebin/bootstrap.dylib"))
    {
		if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
			void __interpose();
			__interpose();
		}
    }

    if(getppid() != 1) {
        void fixsuid();
        fixsuid();
    }

    if(strcmp(getprogname(), "launchctl")==0)
    {
        fprintf(stderr, "launchctl is not supported yet.\n");
        exit(0);
    }

    if(strcmp(getprogname(), "dpkg")==0)
    {
		extern int (*dpkghook_orig_close)(int fd);
		extern int dpkghook_new_close(int fd);

		extern int (*dpkghook_orig_rmdir)(char* path);
		extern int dpkghook_new_rmdir(char* path);

        struct rebinding rebindings[] = {
            {"close", dpkghook_new_close, (void**)&dpkghook_orig_close},
			{"rmdir", dpkghook_new_rmdir, (void**)&dpkghook_orig_rmdir},
        };
        struct mach_header_64* header = _dyld_get_prog_image_header();
        rebind_symbols_image((void*)header, _dyld_get_image_slide(header), rebindings, sizeof(rebindings)/sizeof(rebindings[0]));
    } 
	else if(strcmp(getprogname(), "uicache")==0)
    {
    	extern void runAsRoot();
		runAsRoot();

		extern void (*apphook_orig_objc_msgSend)();
		extern void apphook_new_objc_msgSend();

        struct rebinding rebindings[] = {
            {"objc_msgSend", apphook_new_objc_msgSend, (void**)&apphook_orig_objc_msgSend},
        };
        struct mach_header_64* header = _dyld_get_prog_image_header();
        rebind_symbols_image((void*)header, _dyld_get_image_slide(header), rebindings, sizeof(rebindings)/sizeof(rebindings[0]));
    }


	dlopen(jbroot("/usr/lib/roothideinit.dylib"), RTLD_NOW);

	//load first
	if(!dlopen(jbroot("/usr/lib/roothidepatch.dylib"), RTLD_NOW)) { // require jit
		assert(checkpatchedexe());
	}

	if(getppid() == 1) {
		const char* tweakloader = jbroot("/usr/lib/TweakLoader.dylib");
		if(access(tweakloader, F_OK)==0 && jbdswDebugMe()==0) {
			//currenly ellekit/oldabi uses JBROOT
			const char* oldJBROOT = getenv("JBROOT");
			setenv("JBROOT", jbroot("/"), 1);
			dlopen(tweakloader, RTLD_NOW);
			if(oldJBROOT) setenv("JBROOT", oldJBROOT, 1); else unsetenv("JBROOT");
		}
	}

	unsetenv("DYLD_INSERT_LIBRARIES");
}
