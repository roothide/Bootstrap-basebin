#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <util.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/syslimits.h>
#include <spawn.h>
#include <paths.h>
#include <dlfcn.h>
#include <roothide.h>
#include "common.h"
#include "sandbox.h"
#include "../bootstrapd/libbsd.h"

#include <CoreFoundation/CoreFoundation.h>

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


//dopamine interface
EXPORT int jbdswDebugMe()
{
	return requireJIT();
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
#ifdef __arm64e__
DYLD_INTERPOSE(fork_hook, fork)
DYLD_INTERPOSE(vfork_hook, vfork)
DYLD_INTERPOSE(forkpty_hook, forkpty)
DYLD_INTERPOSE(daemon_hook, daemon)
#endif


int requireJIT()
{
	static int result = -1;
	static int inited = 0;
	if(inited++) return result;
	return (result=bsd_enableJIT());
}

bool checkpatchedexe() {
	char executablePath[PATH_MAX]={0};
	uint32_t bufsize=sizeof(executablePath);
	ASSERT(_NSGetExecutablePath(executablePath, &bufsize) == 0);
	
	char patcher[PATH_MAX];
	snprintf(patcher, sizeof(patcher), "%s.roothidepatch", executablePath);
	if(access(patcher, F_OK)==0) 
		return false;

	return true;
}

extern void runAsRoot(const char* path, char* argv[]);

char* excludeProcesses[] = {
	"/usr/sbin/dropbear",
	"/usr/sbin/sshd",
	"/usr/bin/fish",
	"/usr/bin/dash",
	"/usr/bin/bash",
	"/usr/bin/zsh",
};

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return requireJIT();
}

#include <pwd.h>
#include <libgen.h>
#include <stdio.h>

#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon

void redirectEnvPath(const char* rootdir)
{
    // char executablePath[PATH_MAX]={0};
    // uint32_t bufsize=sizeof(executablePath);
    // if(_NSGetExecutablePath(executablePath, &bufsize)==0 && strstr(executablePath,"testbin2"))
    //     printf("redirectNSHomeDir %s, %s\n\n", rootdir, getenv("CFFIXED_USER_HOME"));

    //for now libSystem should be initlized, container should be set.

    char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory will return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
    if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
    {
        homedir = getenv("CFFIXED_USER_HOME");
        if(homedir)
        {
            if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
            {
                return; //containerized
            }
            else
            {
                homedir = NULL; //from parent, drop it
            }
        }
    }

    if(!homedir) {
        struct passwd* pwd = getpwuid(geteuid());
        if(pwd && pwd->pw_dir) {
            homedir = pwd->pw_dir;
        }
    }

    // if(!homedir) {
    //     //CFCopyHomeDirectoryURL does, but not for NSHomeDirectory
    //     homedir = getenv("HOME");
    // }

    if(!homedir) {
        homedir = "/var/empty";
    }

    char newhome[PATH_MAX]={0};
    snprintf(newhome,sizeof(newhome),"%s/%s",rootdir,homedir);
    setenv("CFFIXED_USER_HOME", newhome, 1);
}

void redirectDirs(const char* rootdir)
{
    do { // only for jb process because some system process may crash when chdir
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX];
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX];
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[strlen(realjbroot)] != '/')
            strcat(realjbroot, "/");
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;
    
        pid_t ppid = getppid();
        assert(ppid > 0);

		//for jailbroken binaries
		redirectEnvPath(rootdir);

        if(ppid == 1) {
			char pwd[PATH_MAX];
			if(getcwd(pwd, sizeof(pwd)) == NULL)
				break;
			if(strcmp(pwd, "/") != 0)
				break;
		
			assert(chdir(rootdir)==0);
		}
        
    } while(0);
}

// const char* bootstrapath=NULL;
static void __attribute__((__constructor__)) bootstrap()
{
    char executablePath[PATH_MAX]={0};
    uint32_t bufsize=sizeof(executablePath);
    ASSERT(_NSGetExecutablePath(executablePath, &bufsize) == 0);

	const char* exepath = rootfs(executablePath);

    // SYSLOG("bootstrap....%s\n", exepath);
	// SYSLOG("HOME=%s\n%s\n%s", getenv("HOME"), getenv("CFFIXED_USER_HOME"), getenv("TMPDIR"));
	
	// struct dl_info di={0};
    // dladdr((void*)bootstrap, &di);
	// bootstrapath = strdup(di.dli_fname);

	const char* bundleIdentifier = NULL;
	CFBundleRef mainBundle = CFBundleGetMainBundle();
	if(mainBundle) {
		CFStringRef cfBundleIdentifier = CFBundleGetIdentifier(mainBundle);
		if(cfBundleIdentifier)
			bundleIdentifier = CFStringGetCStringPtr(cfBundleIdentifier, kCFStringEncodingASCII);
	}
	SYSLOG("bundleIdentifier=%s", bundleIdentifier?bundleIdentifier:"(null)");

	if(!bundleIdentifier || !stringStartsWith(bundleIdentifier, "com.apple.")) {
		redirectDirs(jbroot("/"));
	}

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

    if(strcmp(exepath, "/usr/bin/launchctl")==0)
    {
		if(access(jbroot("/basebin/.launchctl_support"), F_OK) != 0) 
		{
			if(NXArgc >= 3 && strcmp(NXArgv[1],"reboot")==0 && strcmp(NXArgv[2],"userspace")==0) 
			{
				char* args[] = {"/usr/bin/killall", "-9", "backboardd", NULL};
				runAsRoot(jbroot(args[0]), args);
			}

			fprintf(stderr, "launchctl is not supported.\n");
			exit(0);
		}
    }
	else if(strcmp(exepath, "/usr/bin/dpkg")==0)
    {
		void init_dpkg_hook();
		init_dpkg_hook();
    } 
	else if(strcmp(exepath, "/usr/bin/uicache")==0)
    {
		runAsRoot(jbroot("/basebin/uicache"), NXArgv);
    }
	else if(strcmp(exepath, "/Applications/Preferences.app/Preferences")==0 || strcmp(exepath, "/Applications/TweakSettings.app/TweakSettings")==0)
    {
		void init_prefshook();
		init_prefshook();
    }

	dlopen(jbroot("/usr/lib/roothideinit.dylib"), RTLD_NOW);

	//load first
	if(!dlopen(jbroot("/usr/lib/roothidepatch.dylib"), RTLD_NOW)) { // require jit
		ASSERT(checkpatchedexe());
	}

	if(getppid()==1)
	{
		if(bundleIdentifier)
		{
			if(stringStartsWith(bundleIdentifier, "com.apple.") && strcmp(bundleIdentifier, "com.apple.springboard")!=0)
			{
				void init_platformHook();
				init_platformHook(); //try
			} 
			else if(stringStartsWith(exepath, "/Applications/"))
			{
				ASSERT(bsd_checkServer()==0);
			}
		}

		if(access(jbroot("/var/mobile/.tweakenabled"), F_OK)==0)
		{
			bool excluded = false;
			for(int i=0; i<sizeof(excludeProcesses)/sizeof(excludeProcesses[0]); i++)
			{
				if(strcmp(exepath, excludeProcesses[i])==0) {
					excluded=true;
					break;
				}
			}

			const char* tweakloader = jbroot("/usr/lib/TweakLoader.dylib");
			if(!excluded && requireJIT()==0 && access(tweakloader, F_OK)==0) { //fix frida: always enable JIT before checking tweakloader
				//currenly ellekit/oldabi uses JBROOT
				const char* oldJBROOT = getenv("JBROOT");
				setenv("JBROOT", jbroot("/"), 1);
				dlopen(tweakloader, RTLD_NOW);
				if(oldJBROOT) setenv("JBROOT", oldJBROOT, 1); else unsetenv("JBROOT");
			}
		}
	}

	unsetenv("DYLD_INSERT_LIBRARIES");
}
