#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <util.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <sys/syslimits.h>
#include <spawn.h>
#include <paths.h>
#include <dlfcn.h>
#include <pwd.h>
#include <stdio.h>
#include <libgen.h>
#include <roothide.h>
#include "common.h"
#include "sandbox.h"
#include "libproc.h"
#include "libbsd.h"
#include "jbclient.h"

#include <CoreFoundation/CoreFoundation.h>

char* g_executable_path = NULL;
char* g_sandbox_extensions = NULL;


int sandbox_init_hook(const char *profile, uint64_t flags, char **errorbuf)
{
	int retval = sandbox_init(profile, flags, errorbuf);
	if (retval == 0) {
		if(g_sandbox_extensions) {
			unsandbox(g_sandbox_extensions);
		}
	}
	return retval;
}

int sandbox_init_with_parameters_hook(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf)
{
	int retval = sandbox_init_with_parameters(profile, flags, parameters, errorbuf);
	if (retval == 0) {
		if(g_sandbox_extensions) {
			unsandbox(g_sandbox_extensions);
		}
	}
	return retval;
}

//removed api on ios18, define as weak symbol
__attribute__((weak,weak_import)) int sandbox_init_with_extensions(const char *profile, uint64_t flags, const char *const extensions[], char **errorbuf) asm("_sandbox_init_with_extensions");
int sandbox_init_with_extensions_hook(const char *profile, uint64_t flags, const char *const extensions[], char **errorbuf)
{
	int retval = sandbox_init_with_extensions(profile, flags, extensions, errorbuf);
	if (retval == 0) {
		if(g_sandbox_extensions) {
			unsandbox(g_sandbox_extensions);
		}
	}
	return retval;
}

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


static uid_t _CFGetSVUID(bool *successful) {
    uid_t uid = -1;
    struct kinfo_proc kinfo;
    u_int miblen = 4;
    size_t  len;
    int mib[miblen];
    int ret;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    len = sizeof(struct kinfo_proc);
    ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
    if (ret != 0) {
        uid = -1;
        *successful = false;
    } else {
        uid = kinfo.kp_eproc.e_pcred.p_svuid;
        *successful = true;
    }
    return uid;
}

bool _CFCanChangeEUIDs(void) {
    static bool canChangeEUIDs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uid_t euid = geteuid();
        uid_t uid = getuid();
        bool gotSVUID = false;
        uid_t svuid = _CFGetSVUID(&gotSVUID);
        canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
    });
    return canChangeEUIDs;
}

void loadPathHook()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		void* roothidehooks = dlopen(jbroot("/basebin/roothidehooks.dylib"), RTLD_NOW);
		ASSERT(roothidehooks != NULL);
		void (*pathhook)() = dlsym(roothidehooks, "pathhook");
		ASSERT(pathhook != NULL);
		pathhook();
	});
}

#include <pwd.h>
#include <libgen.h>
#include <stdio.h>

void redirect_path_env(const char* rootdir)
{
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
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
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

	if(homedir[0] == '/') {
		char newhome[PATH_MAX*2]={0};
		strlcpy(newhome, rootdir, sizeof(newhome));
		strlcat(newhome, homedir, sizeof(newhome));
		setenv("CFFIXED_USER_HOME", newhome, 1);
	}
}

void redirect_paths(const char* rootdir)
{
    do {
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX]={0};
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX+1]={0};
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[0] && realjbroot[strlen(realjbroot)-1] != '/')
            strlcat(realjbroot, "/", sizeof(realjbroot));
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;

        //for jailbroken binaries
        redirect_path_env(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			// void loadPathHook();
			// loadPathHook();
		}
    
        pid_t ppid = get_real_ppid();
        assert(ppid > 0);
        if(ppid != 1)
            break;
        
        char pwd[PATH_MAX];
        if(getcwd(pwd, sizeof(pwd)) == NULL)
            break;
        if(strcmp(pwd, "/") != 0)
            break;
    
        assert(chdir(rootdir)==0);
        
    } while(0);
}

char* remove_trailing_slash(char *path) {
    size_t len = strlen(path);
    if (len > 0 && path[len - 1] == '/') {
        path[len - 1] = '\0';
    }
    return path;
}

extern void runAsRoot(const char* path, char* argv[]);

char* tweakDisabledProcesses[] = {
	"/Applications/Terminal.app/Terminal",
	"/Applications/MTerminal.app/MTerminal",
};

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return requireJIT();
}

static void __attribute__((__constructor__)) bootstrap()
{
    char executablePath[PATH_MAX]={0};
    uint32_t bufsize=sizeof(executablePath);
    ASSERT(_NSGetExecutablePath(executablePath, &bufsize) == 0);

	g_executable_path = strdup(executablePath);
	
	const char* sbtoken = getenv("__SANDBOX_EXTENSIONS");
	if(sbtoken) {
		g_sandbox_extensions = strdup(sbtoken);
	}

	//do nothing extra inside xpcproxy (do not enable syslog in xpcproxy)
	if(string_has_suffix(executablePath, "/usr/libexec/xpcproxy")) {
		return;
	}

#if DEBUG
	enableCommLog(bootstrapLog, bootstrapLog);
	bootstrapLogFunction = bootstrapLog;
	SYSLOG("Bootstrap loaded... sandboxed=%d containerized=%d", proc_is_sandboxed(), proc_is_containerized());
#endif

	const char* exepath = rootfs(executablePath);

	ASSERT(!string_has_prefix(exepath, "/basebin/"));

	if(sbtoken)
	{
		unsandbox(sbtoken);

		if(!string_has_prefix(exepath, "/.sysroot/")) {
			ASSERT(bsd_tick_mach_service());
		}
	}

	const char* bundleIdentifier = NULL;
	CFBundleRef mainBundle = CFBundleGetMainBundle();
	if(mainBundle) {
		CFStringRef cfBundleIdentifier = CFBundleGetIdentifier(mainBundle);
		if(cfBundleIdentifier)
			bundleIdentifier = CFStringGetCStringPtr(cfBundleIdentifier, kCFStringEncodingASCII);
	}

	if(!bundleIdentifier) {
		const char* identifier = proc_get_identifier(getpid(), NULL);
		if(identifier) {
			bundleIdentifier = strdup(identifier);
		}
	}

	SYSLOG("bundleIdentifier = %s", bundleIdentifier ? bundleIdentifier : "null");

	bool appFromTrollStore = hasTrollstoreMarker(executablePath);

	if(!bundleIdentifier || !string_has_prefix(bundleIdentifier, "com.apple.") || is_apple_internal_identifier(bundleIdentifier) || appFromTrollStore) {
		char jbrootdir[PATH_MAX] = {0};
		strlcat(jbrootdir, jbroot("/"), sizeof(jbrootdir));
		remove_trailing_slash(jbrootdir);
		redirect_paths(jbrootdir);
	}

	const char* preload = getenv("DYLD_INSERT_LIBRARIES");
	if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0)
	{
		void hook_NSTask(void);
		 hook_NSTask();
		 
		if(!preload || !strstr(preload,"/basebin/bootstrap.dylib"))
		{
			void _dynamic_interpose();
			_dynamic_interpose();
		}
    }

    if(get_real_ppid() != 1) {
        void fixsuid();
        fixsuid();
    }

    if(strcmp(exepath, "/usr/bin/launchctl")==0)
    {
		if(!launchctl_support()) 
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
    else if(strcmp(exepath, "/usr/bin/ldrestart")==0)
    {
		if(!launchctl_support()) 
		{
			char* args[] = {"/usr/bin/killall", "-9", "backboardd", NULL};
			runAsRoot(jbroot(args[0]), args);

			fprintf(stderr, "ldrestart is not supported.\n");
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
	else if(strcmp(exepath, "/usr/sbin/shshd")==0)
	{
		fprintf(stderr, "shshd is not supported on current device.\n");
		exit(0);
	}
	else if(string_has_suffix(exepath, "/usr/libexec/watchdogd")) {
		//init watchdogd hook
	}

	//checkServer before loading roothidepatch
	if(get_real_ppid()==1)
	{
		if(bundleIdentifier)
		{
			if(string_has_prefix(bundleIdentifier, "com.apple.") && !is_apple_internal_identifier(bundleIdentifier))
			{
				void init_platformHook();
				init_platformHook(); //try
				
				void init_process_path_hook();
				init_process_path_hook();
			} 
			else if(string_has_prefix(exepath, "/Applications/"))
			{
				if(bsd_checkServer() != 0) {
					void launchBootstrapApp();
					launchBootstrapApp();
					abort();
				}

				void varCleanInit();
				varCleanInit();
			}
			else if(appFromTrollStore) {
				void varCleanInit();
				varCleanInit();
			}
		}
	}

	dlopen(jbroot("/usr/lib/roothideinit.dylib"), RTLD_NOW);

	if (string_has_suffix(exepath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard")
		|| string_has_suffix(exepath, "/usr/sbin/cfprefsd")
		|| string_has_suffix(exepath, "/usr/libexec/lsd"))
	{
		ASSERT(requireJIT()==0);
		dlopen(jbroot("/basebin/roothidehooks.dylib"), RTLD_NOW);
	}

	//load first
	if(!dlopen(jbroot("/usr/lib/roothidepatch.dylib"), RTLD_NOW)) { // require jit
		ASSERT(checkpatchedexe(executablePath));
	}
	
	// if(!string_has_suffix(executablePath, "/usr/sbin/cfprefsd")) {
	if(!launchctl_support()) {
		void init_prefs_objchook();
		init_prefs_objchook();
	}

	do {
		//fix frida: always enable JIT first
		if(requireJIT() != 0) {
			SYSLOG("Failed to enable JIT");
			break;
		}

		if(get_real_ppid() != 1) {
			SYSLOG("Not loading tweaks for non launched job process: pid=%d ppid=%d", getpid(), get_real_ppid());
			break;
		}

		if(!is_app_coalition() && !string_has_prefix(exepath, "/.sysroot/")) {
			SYSLOG("Not loading tweaks for process from deb packages");
			break;
		}

		bool blockTweaks = false;
		for(int i=0; i<sizeof(tweakDisabledProcesses)/sizeof(tweakDisabledProcesses[0]); i++)
		{
			if(strcmp(exepath, tweakDisabledProcesses[i])==0) {
				SYSLOG("Tweaks disabled for %s", exepath);
				blockTweaks=true;
				break;
			}
		}
		if(blockTweaks) {
			break;
		}

		// if(!string_has_suffix(executablePath, "/usr/sbin/cfprefsd")) {
		if(!launchctl_support()) {
			void init_prefs_inlinehook();
			init_prefs_inlinehook();
		}
		
		char *tweaksDisabledEnv = getenv("DISABLE_TWEAKS");
		if (tweaksDisabledEnv) {
			if (!strcmp(tweaksDisabledEnv, "1")) {
				break;
			}
		}
		const char *safeModeValue = getenv("_SafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				break;
			}
		}
		const char *msSafeModeValue = getenv("_MSSafeMode");
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				break;
			}
		}
	
		if(access(jbroot("/var/mobile/.tweakenabled"), F_OK)==0)
		{
			const char* tweakloader = jbroot("/usr/lib/TweakLoader.dylib");
			if(access(tweakloader, F_OK)==0) {
				dlopen(tweakloader, RTLD_NOW);
			}
		}

	} while(0);

	// const char* profile = roothide_get_sandbox_profile(getpid(), NULL);
	// if(profile)
	// {
	// 	char* errormsg = NULL;
	// 	if(sandbox_init(profile, SANDBOX_NAMED, &errormsg) == 0) {
	// 		SYSLOG("sandbox_init succeeded: %s\n", profile);
	// 		unsandbox(sbtoken);
	// 	} else {
	// 		SYSLOG("sandbox_init failed: %s, err=%s\n", profile, errormsg);
	// 		free(errormsg);
	// 	}
	// }

	if(preload && strstr(preload,"/basebin/bootstrap.dylib") && !strstr(preload,":")) {
		unsetenv("DYLD_INSERT_LIBRARIES");
	}
	if(sbtoken) {
		unsetenv("__SANDBOX_EXTENSIONS");
	}
}


#define DYLD_INTERPOSE(_replacement,_replacee) \
	__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
	__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

DYLD_INTERPOSE(posix_spawn_hook, posix_spawn)
DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp)
DYLD_INTERPOSE(execve_hook, execve)
DYLD_INTERPOSE(execle_hook, execle)
DYLD_INTERPOSE(execlp_hook, execlp)
DYLD_INTERPOSE(execv_hook, execv)
DYLD_INTERPOSE(execl_hook, execl)
DYLD_INTERPOSE(execvp_hook, execvp)
DYLD_INTERPOSE(execvP_hook, execvP)
DYLD_INTERPOSE(sandbox_init_hook, sandbox_init)
DYLD_INTERPOSE(sandbox_init_with_parameters_hook, sandbox_init_with_parameters)
DYLD_INTERPOSE(sandbox_init_with_extensions_hook, sandbox_init_with_extensions)
#ifdef __arm64e__
DYLD_INTERPOSE(fork_hook, fork)
DYLD_INTERPOSE(vfork_hook, vfork)
DYLD_INTERPOSE(forkpty_hook, forkpty)
DYLD_INTERPOSE(daemon_hook, daemon)
#endif