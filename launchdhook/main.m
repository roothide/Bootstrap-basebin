#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <roothide.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <xpc/xpc.h>
#include <libgen.h>
#include <spawn.h>

#include "crashreporter.h"
#include "codesign.h"
#include "commlib.h"
#include "envbuf.h"

int (*orig_csops)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize) = csops;
int new_csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize)
{
	int ret = orig_csops(pid, ops, useraddr, usersize);
	if(ret==0 && ops==CS_OPS_STATUS) {
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
    if(ret==0 && ops==CS_OPS_STATUS) {
        *(uint32_t*)useraddr |= CS_VALID;
        *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
        *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
    }

    return ret;
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

int (*orig_posix_spawn)(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) = posix_spawn;
int orig_posix_spawn_wrapper(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	short flags = -1;
	if(attrp) posix_spawnattr_getflags(attrp, &flags);
	FileLogDebug("launchd spawn path=%s flags=%x", path, flags);
	if (argv) for (int i = 0; argv[i]; i++) FileLogDebug("\targs[%d] = %s", i, argv[i]);
	if (envp) for (int i = 0; envp[i]; i++) FileLogDebug("\tenvp[%d] = %s", i, envp[i]);

	pid_t pid = 0;

	crashreporter_pause();
	int ret = orig_posix_spawn(&pid, path, file_actions, attrp, argv, envp);
	crashreporter_resume();

	FileLogDebug("posix_spawn(%s) ret=%d pid=%d", path, ret, pid);

	if(pidp) *pidp = pid;
	return ret;
}

const char* basebinDaemons[] = {
	"com.roothide.bootstrap.startup",
	"com.roothide.bootstrap.bootstrapd",
	NULL
};

bool should_inject_bootstrap(const char* path, char*const* argv, bool resigned)
{
	if(strcmp(path, "/usr/libexec/xpcproxy") == 0)
	{
		if(!argv || !argv[0] || !argv[1]) return false;

		const char* bundle = argv[1];

		for(int i=0; basebinDaemons[i]; i++) {
			if(strcmp(bundle, basebinDaemons[i])==0) {
				return false;
			}
		}

		return resigned;
	}

	if(string_has_suffix(path, "/Bootstrap.app/Bootstrap")) {
		return false;
	}

	return resigned;
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
	
	char* temp=NULL;
	asprintf(&temp, "/.sysroot%s", path);
	char* resigned_path = jbroot(temp);
	free(temp);

	bool resigned = isSubPathOf(resigned_path, jbroot("/.sysroot/"));

	if (__builtin_available(iOS 16.0, *)) {
		if(resigned) {
			posix_spawnattr_set_launch_type_np(attrp, 0);
		}
	}

	if(should_inject_bootstrap(path, argv, resigned))
	{
		const char* bootstrapath = jbroot("/basebin/bootstrap.dylib");
		const char* preload = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
		if(preload && *preload) {
			char newpreload[strlen(preload)+strlen(bootstrapath)+2];
			snprintf(newpreload, sizeof(newpreload), "%s:%s", bootstrapath, preload);
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newpreload, 1);
		} else {
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", bootstrapath, 1);
		}
	}

	int ret = orig_posix_spawn_wrapper(pidp, resigned ? resigned_path : path, file_actions, attrp, argv, envc);

	if(attr) posix_spawnattr_destroy(&attr);

	envbuf_free(envc);

	return ret;
}

int (*orig_posix_spawnp)(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) = posix_spawnp;
int new_posix_spawnp(pid_t *restrict pidp, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	return resolvePath(path, NULL, ^int(char *file) {
		return new_posix_spawn(pidp, file, file_actions, attrp, argv, envp);
	});
}

__attribute__((constructor)) static void initializer(void)
{
	CommLogFunction = FileLogDebugFunction;
	FileLogDebug("launchdhook initializing");

	crashreporter_start();

	if (access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist", W_OK)==0) {
		remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist");
	}
	if (access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist", W_OK)==0) {
		remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist");
	}

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
// DYLD_INTERPOSE(new_sandbox_check_by_audit_token, sandbox_check_by_audit_token)
