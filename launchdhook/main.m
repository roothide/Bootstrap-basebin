#include <private/bsm/audit.h>
#include <kern_memorystatus.h>
#include <sys/clonefile.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <xpc/xpc.h>
#include <sandbox.h>
#include <libgen.h>
#include <spawn.h>

#include <roothide.h>
#include <Foundation/Foundation.h>

#include "crashreporter.h"
#include "jailbreakd.h"
#include "codesign.h"
#include "envbuf.h"
#include "ptrace.h"
#include "common.h"
#include "dobby.h"


const char* g_sandbox_extensions = NULL;
const char* g_sandbox_extensions_ext = NULL;

extern xpc_object_t (*orig_xpc_dictionary_create_reply)(xpc_object_t original);
extern xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original);
extern int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);
extern int new_xpc_pipe_routine_reply(xpc_object_t reply);

int (*orig_csops)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize) = csops;
int new_csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize)
{
	int ret = orig_csops(pid, ops, useraddr, usersize);

	if(isBlacklistedPid(pid)) {
		return ret;
	}

	if(ret==0 && ops==CS_OPS_STATUS && useraddr) {
		*(uint32_t*)useraddr |= CS_VALID;
		*(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
		*(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
	}

	return ret;
}

int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token) = csops_audittoken;
int new_csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token)
{
    int ret = orig_csops_audittoken(pid, ops, useraddr, usersize, token);

	if(isBlacklistedToken(token)) {
		return ret;
	}

    if(ret==0 && ops==CS_OPS_STATUS && useraddr) {
        *(uint32_t*)useraddr |= CS_VALID;
        *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
        *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
    }

    return ret;
}

int (*orig_sandbox_check_by_audit_token)(audit_token_t au, const char *operation, int sandbox_filter_type, ...) = sandbox_check_by_audit_token;
int new_sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...)
{
	va_list a;
	va_start(a, sandbox_filter_type);
	const char *name = va_arg(a, const char *);
	const void *arg2 = va_arg(a, void *);
	const void *arg3 = va_arg(a, void *);
	const void *arg4 = va_arg(a, void *);
	const void *arg5 = va_arg(a, void *);
	const void *arg6 = va_arg(a, void *);
	const void *arg7 = va_arg(a, void *);
	const void *arg8 = va_arg(a, void *);
	const void *arg9 = va_arg(a, void *);
	const void *arg10 = va_arg(a, void *);
	va_end(a);

	if (name && operation) {
		if(isBlacklistedToken(&au)) {
			FileLogDebug(strstr(operation, "mach-") ? "sandbox_check_by_audit_token operation=%s name=%s from %s" : "sandbox_check_by_audit_token operation=%s name=%p from %s", operation, name, proc_get_path(audit_token_to_pid(au),NULL));
		} else {
			if (strcmp(operation, "mach-lookup") == 0) {
				if (strncmp((char *)name, "cy:", 3) == 0 || strncmp((char *)name, "lh:", 3) == 0) {
					/* always allow */
					return 0;
				}
			}
		}
	}

	return orig_sandbox_check_by_audit_token(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

void xpc_dictionary_add_launch_daemon_plist_at_path(xpc_object_t xdict, const char *path)
{
	int ldFd = open(path, O_RDONLY);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		if (addr != MAP_FAILED) {
			xpc_object_t daemonXdict = xpc_create_from_plist(addr, len);
			if (daemonXdict) {
				xpc_dictionary_set_value(xdict, path, daemonXdict);
			}
			munmap(addr, len);
		}
		close(ldFd);
	}
}

xpc_object_t (*orig_xpc_dictionary_get_value)(xpc_object_t xdict, const char *key) = xpc_dictionary_get_value;
xpc_object_t new_xpc_dictionary_get_value(xpc_object_t xdict, const char *key)
{
	xpc_object_t origXvalue = orig_xpc_dictionary_get_value(xdict, key);
	if (strcmp(key, "LaunchDaemons") == 0) {
		if (xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY) {
			for (NSString *daemonPlistName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbroot(@"/basebin/LaunchDaemons") error:nil]) {
				if ([daemonPlistName.pathExtension isEqualToString:@"plist"]) {
					xpc_dictionary_add_launch_daemon_plist_at_path(origXvalue, [jbroot(@"/basebin/LaunchDaemons") stringByAppendingPathComponent:daemonPlistName].fileSystemRepresentation);
				}
			}
		}
		char* desc=NULL;
		// FileLogDebug("launch LaunchDaemons = %s", xpc_copy_description(origXvalue));
		if(desc) free(desc);
	}
	else if (strcmp(key, "Paths") == 0) {
		if (xpc_get_type(origXvalue) == XPC_TYPE_ARRAY) {
			xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, jbroot("/basebin/LaunchDaemons"));
		}
		char* desc=NULL;
		FileLogDebug("launch Paths = %s", xpc_copy_description(origXvalue));
		if(desc) free(desc);
	}
	else if (strcmp(key, "com.apple.private.xpc.launchd.userspace-reboot") == 0) {
		if (!origXvalue || xpc_get_type(origXvalue) == XPC_TYPE_BOOL) {
			bool origValue = false;
			if (origXvalue) {
				origValue = xpc_bool_get_value(origXvalue);
			}
			if (!origValue) {
				// Allow watchdogd to do userspace reboots
				return orig_xpc_dictionary_get_value(xdict, "com.apple.private.iowatchdog.user-access");
			}
		}
	}
	return origXvalue;
}

int (*oirg_memorystatus_control)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize) = memorystatus_control;
int new_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize)
{
    if (command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT) {
        return 0;
    }
    return oirg_memorystatus_control(command, pid, flags, buffer, buffersize);
}

int jbserver_received_xpc_message(xpc_object_t xmsg);
int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int (*orig_xpc_receive_mach_msg)(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut) = xpc_receive_mach_msg;
int new_xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	int r = orig_xpc_receive_mach_msg(msg, a2, a3, a4, xOut);
	if (r == 0 && xOut && *xOut) {
		if (jbserver_received_xpc_message(*xOut) == 0) {
			// xpc_release(*xOut);
			return 22;
		}
	}
	return r;
}

#define ROOTHIDE_START_SUSPENDED	0x2000 // _POSIX_SPAWN_ALLOW_DATA_EXEC(0x2000) only used in DEBUG/DEVELOPMENT kernel

int (*orig_posix_spawn)(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) = posix_spawn;
int orig_posix_spawn_wrapper(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	short flags=-1;
	void* amfi=NULL;
	void* sandbox=NULL;
	if(attrp) posix_spawnattr_getflags(attrp, &flags);
	if(attrp) posix_spawnattr_getmacpolicyinfo_np(attrp, "AMFI", &amfi, NULL);
	if(attrp) posix_spawnattr_getmacpolicyinfo_np(attrp, "Sandbox", &sandbox, NULL);
	FileLogDebug("launchd spawn path=%s flags=%x sandbox=%p amfi=%p", path, flags, sandbox, amfi);
	if (argv) for (int i = 0; argv[i]; i++) FileLogDebug("\targs[%d] = %s", i, argv[i]);
	if (envp) for (int i = 0; envp[i]; i++) FileLogDebug("\tenvp[%d] = %s", i, envp[i]);

	pid_t pid = 0;

	posix_spawnattr_t attr=NULL;
	if(!attrp) {
		posix_spawnattr_init(&attr);
		attrp = &attr;
	}
	
	posix_spawnattr_setexceptionports_np(attrp, EXC_MASK_ALL, MACH_PORT_NULL, 0, 0);
	// int key = crashreporter_pause();
	int ret = orig_posix_spawn(&pid, path, file_actions, attrp, argv, envp);
	// crashreporter_resume(key);

	FileLogDebug("posix_spawn(%s) ret=%d pid=%d", path, ret, pid);

	if(attr) posix_spawnattr_destroy(&attr);

	if(pidp) *pidp = pid;
	return ret;
}

int new_posix_spawn(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	if(!path) {
		return orig_posix_spawn(pidp, path, file_actions, attrp, argv, envp);
	}

	if(strcmp(path, "/sbin/launchd")==0)
	{
		short flags = -1;
		if(attrp) posix_spawnattr_getflags(attrp, &flags);
		FileLogDebug("********* launchd re-spawning: %s, flags=%x", path, flags);
		 
		signal(SIGTRAP, SIG_IGN);

		posix_spawnattr_t attr;
		posix_spawnattr_init(&attr);
		if (__builtin_available(iOS 16.0, *)) {
			posix_spawnattr_set_launch_type_np(&attr, 0);
		}
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC|POSIX_SPAWN_CLOEXEC_DEFAULT);
		return orig_posix_spawn_wrapper(pidp, jbroot("/.sysroot/sbin/launchd"), file_actions, &attr, argv, envp);
	}

	char **envc = envbuf_mutcopy(envp);

	posix_spawnattr_t attr=NULL;
	if(!attrp) {
		posix_spawnattr_init(&attr);
		attrp = &attr;
	}

	struct stat sb={0};
	if (stat(path, &sb) == 0) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
			if ((sb.st_mode & (S_ISUID))) {
				posix_spawnattr_set_persona_uid_np(attrp, sb.st_uid);
			}
			if ((sb.st_mode & (S_ISGID))) {
				posix_spawnattr_set_persona_gid_np(attrp, sb.st_gid);
			}
		}
	}

	bool should_patch = false;
	bool is_app_path = false;
	bool is_tweaked_app = false;
	const char* newpath = NULL;
	const char* insertlib = NULL;

	// if(strcmp(path, "/usr/libexec/debugserver") == 0)
	// {
	// 	const char* mypath = jbroot("/usr/bin/xcodeanydebug/debugserver");
	// 	if(access(mypath, F_OK)==0) {
	// 		newpath = strdup(mypath);

	// 		if (__builtin_available(iOS 16.0, *)) {
	// 			posix_spawnattr_set_launch_type_np(attrp, 0);
	// 		}
	// 	}
	// }

	if(isRemovableBundlePath(path))
	{
		is_app_path = true;

		char dirnamebuf[PATH_MAX]={0};
		dirname_r(path, dirnamebuf);

		char* tweaked_path=NULL;
		asprintf(&tweaked_path, "%s/.tweaked", dirnamebuf);

		char* original_path=NULL;
		asprintf(&original_path, "%s/.original", dirnamebuf);

		if(access(tweaked_path, F_OK)==0 && access(original_path, F_OK)==0)
		{
			unlink(path);
			clonefile(tweaked_path, path, 0);

			is_tweaked_app = true;
		}

		free(tweaked_path);
		tweaked_path=NULL;
		free(original_path);
		original_path=NULL;

		if(is_tweaked_app)
		{
			newpath = strdup(path);

			asprintf(&insertlib, "%s/.prelib", dirnamebuf);

			envbuf_setenv(&envc, "__SANDBOX_EXTENSIONS", g_sandbox_extensions, 1);
		}
	}
	else
	{
		char* temp=NULL;
		asprintf(&temp, "/.sysroot%s", path);
		const char* resigned_path = jbroot(temp);
		free(temp);
		temp=NULL;

		if(isSubPathOf(resigned_path, jbroot("/.sysroot/")))
		{
			if(strcmp(path, "/usr/libexec/xpcproxy") != 0) {
				should_patch = true;
			}

			newpath = strdup(resigned_path);

			insertlib = strdup(jbroot("/basebin/bootstrap.dylib"));

			envbuf_setenv(&envc, "__SANDBOX_EXTENSIONS", g_sandbox_extensions_ext, 1);

			if (__builtin_available(iOS 16.0, *)) {
				posix_spawnattr_set_launch_type_np(attrp, 0);
			}
		}
		else if(isSubPathOf(path, jbroot("/")))
		{
			newpath = strdup(path);

			insertlib = strdup(jbroot("/basebin/bootstrap.dylib"));

			envbuf_setenv(&envc, "__SANDBOX_EXTENSIONS", g_sandbox_extensions_ext, 1);
		}
	}

	if(newpath && insertlib)
	{
		const char* preload = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
		if(preload && *preload) {
			char newpreload[strlen(preload)+strlen(insertlib)+2];
			snprintf(newpreload, sizeof(newpreload), "%s:%s", insertlib, preload);
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newpreload, 1);
		} else {
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", insertlib, 1);
		}

		uint8_t *attrStruct = *attrp;
		if(attrStruct) {
			int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
			if (memlimit_active != -1) {
				*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * JETSAM_DEFAULT_MULTIPLIER;
			}
			int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
			if (memlimit_inactive != -1) {
				*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * JETSAM_DEFAULT_MULTIPLIER;
			}
		}
	}

	pid_t pid = 0;
	if(!pidp) pidp = &pid;

	volatile pid_t* old_pidp = pidp;
	volatile pid_t* blacklistedPidp = NULL;
	if(is_app_path && isBlacklistedPath(path))
	{
		FileLogDebug("blacklisted app %s", path);

		blacklistedPidp = allocBlacklistProcessId();
		pidp = blacklistedPidp;

		//choicy may set these 
		envbuf_unsetenv(&envc, "_SafeMode");
		envbuf_unsetenv(&envc, "_MSSafeMode");
	}

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	if(should_patch)
	{
		if (should_suspend) {
			short newflags = flags | POSIX_SPAWN_START_SUSPENDED;
			if(proc_debugged(getpid())) {
				newflags |= ROOTHIDE_START_SUSPENDED;
			}
			posix_spawnattr_setflags(attrp, newflags);
		}
	}

	int ret = orig_posix_spawn_wrapper(pidp, newpath ?: path, file_actions, attrp, argv, envc);

	if(blacklistedPidp)
	{
		pidp = old_pidp;
		if(pidp) *pidp = *blacklistedPidp;

		commitBlacklistProcessId(blacklistedPidp); // will release blacklistedPidp
		blacklistedPidp = NULL;
	}

	if(attr) posix_spawnattr_destroy(&attr);
	if(insertlib) free((void*)insertlib);
	if(newpath) free((void*)newpath);

	envbuf_free(envc);

	if(is_tweaked_app)
	{
		char dirnamebuf[PATH_MAX]={0};
		dirname_r(path, dirnamebuf);

		char* original_path=NULL;
		asprintf(&original_path, "%s/.original", dirnamebuf);

		if(access(original_path, F_OK) == 0)
		{
			unlink(path);
			link(original_path, path);
		}

		free(original_path);
	}

	if(should_patch)
	{
		pid_t pid = *pidp;
		if(ret == 0 && pid > 0) {
			if (should_suspend) {
				if(jbdSpawnPatchChild(pid, should_resume) != 0) { // jdb fault? kill
					//just kill it instead of letting it hang forever, and the requester decides what to do later
					kill(pid, SIGQUIT); //core dump
					kill(pid, SIGKILL);
					return 202;
				}
			}
		}
	}

	return ret;
}

int (*orig_posix_spawnp)(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) = posix_spawnp;
int new_posix_spawnp(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	return resolvePath(path, NULL, ^int(char *file) {
		return new_posix_spawn(pidp, file, file_actions, attrp, argv, envp);
	});
}


struct _posix_spawn_args_desc {
	size_t attr_size;
	posix_spawnattr_t attrp;
	//....
};

int __posix_spawn(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
int (*__posix_spawn_hook_orig)(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
int __posix_spawn_hook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	pid_t pid = 0;
	int ret = __posix_spawn_hook_orig(&pid, path, desc, argv, envp);

	if(ret==0 && pid>0 && desc) 
	{
		short flags = 0;
		posix_spawnattr_t attrp = &desc->attrp;
		posix_spawnattr_getflags(attrp, &flags);

		if((flags&ROOTHIDE_START_SUSPENDED) != 0)
			posix_spawnattr_setflags(&(desc->attrp), flags & ~ROOTHIDE_START_SUSPENDED);

		if((flags & POSIX_SPAWN_START_SUSPENDED) != 0 && (flags & ROOTHIDE_START_SUSPENDED) == 0) {
			uint32_t csflags = 0;
			int csret=csops(pid, CS_OPS_STATUS, &csflags, sizeof(csflags));
			//launchd may spawn non-daemon processes with POSIX_SPAWN_START_SUSPENDED at early boot
			if(csret==0 && (csflags & CS_PLATFORM_BINARY)==0) {
				jbdProcessEnableJIT(pid, true);
			}
		}
	}

	if(pidp) *pidp = pid;
	return ret;
}

__attribute__((constructor)) static void initializer(void)
{
	FileLogDebug("launchdhook initializing");

#ifdef ENABLE_LOGS
	enableCommLog(FileLogDebugFunction, FileLogErrorFunction);
#endif

	FileLogDebug("launchdhook debugged=%d traced=%d", proc_debugged(getpid()), proc_traced(getpid()));
	if(access(jbroot("/usr/sbin/frida-server"), F_OK)==0)
	{
		ptrace(PT_TRACE_ME, 0, 0, 0);
		ptrace(PT_SIGEXC, 0, 0, 0);
		FileLogDebug("launchdhook debugged=%d traced=%d", proc_debugged(getpid()), proc_traced(getpid()));
	}

	crashreporter_start();

	if(proc_debugged(getpid())) {
		DobbyHook((void*)__posix_spawn, (void*)__posix_spawn_hook, (void**)&__posix_spawn_hook_orig);
	}

	if (access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist", W_OK)==0) {
		remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist");
	}
	if (access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist", W_OK)==0) {
		remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist");
	}

	loadAppStoredIdentifiers();

	g_sandbox_extensions = generate_sandbox_extensions(false);
	g_sandbox_extensions_ext = generate_sandbox_extensions(true);

	ASSERT(roothide_config_set_blacklist_enable(true) == 0);
	
	ASSERT(initJailbreakd(jbserver_received_xpc_message) == 0);

    ASSERT([[NSString new] writeToFile:jbroot(@"/basebin/.launchctl_support") atomically:YES encoding:NSUTF8StringEncoding error:nil]);

	FileLogDebug("launchdhook initialized");
}


#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
	__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

DYLD_INTERPOSE(new_csops, csops)
DYLD_INTERPOSE(new_csops_audittoken, csops_audittoken)
DYLD_INTERPOSE(new_posix_spawn, posix_spawn)
DYLD_INTERPOSE(new_posix_spawnp, posix_spawnp)
DYLD_INTERPOSE(new_xpc_dictionary_get_value, xpc_dictionary_get_value)
DYLD_INTERPOSE(new_sandbox_check_by_audit_token, sandbox_check_by_audit_token)
DYLD_INTERPOSE(new_xpc_receive_mach_msg, xpc_receive_mach_msg)
DYLD_INTERPOSE(new_xpc_pipe_routine_reply, xpc_pipe_routine_reply)
DYLD_INTERPOSE(new_xpc_dictionary_create_reply, xpc_dictionary_create_reply)
DYLD_INTERPOSE(new_memorystatus_control, memorystatus_control)
