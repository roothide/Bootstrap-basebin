#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <util.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <spawn.h>
#include <paths.h>

#include <roothide.h>

#include "common.h"
#include "envbuf.h"

int posix_spawn_hook(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	SYSLOG("posix_spawn_hook: %s\n", path);

	if(!path) {
		return posix_spawn(pid, path, file_actions, attrp, argv, envp);
	}

	bool should_inject = true;

	char executablePath[PATH_MAX]={0};
	uint32_t bufsize=sizeof(executablePath);
	ASSERT(_NSGetExecutablePath(executablePath, &bufsize) == 0);

	if(isSubPathOf(path, jbroot("/")))
	{
		if(string_has_suffix(executablePath, "/usr/libexec/xpcproxy"))
		{
			if(__builtin_available(iOS 16.0, *)) {
				if(attrp) {
					posix_spawnattr_set_launch_type_np(attrp, 0);
				}
			}
		}

		if(string_has_prefix(rootfs(path), "/basebin/")) {
			should_inject = false;
		}
	}
	else
	{
		should_inject = false;
	}

    char **envc = envbuf_mutcopy(envp);

	const char* preload = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");

	if(should_inject)
	{
		if(!preload || !strstr(preload, "/basebin/bootstrap.dylib"))
		{
			const char* bootstrapath = jbroot("/basebin/bootstrap.dylib");
			if(preload && *preload) {
				char newpreload[strlen(preload)+strlen(bootstrapath)+2];
				snprintf(newpreload, sizeof(newpreload), "%s:%s", bootstrapath, preload);
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newpreload, 1);
			} else {
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", bootstrapath, 1);
			}
		}
	}
	else
	{
		if(preload && strstr(preload, "/basebin/bootstrap.dylib"))
		{
			if(strstr(preload, ":"))
			{
				char* newpreload = malloc(strlen(preload)+1);
				newpreload[0] = 0;

				string_enumerate_components(preload, ":", ^(const char *lib, bool *stop) {
					if (!strstr(lib, "/basebin/bootstrap.dylib")) {
						if (newpreload[0]) {
							strcat(newpreload, ":");
						}
						strcat(newpreload, lib);
					}
				});

				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newpreload, 1);

				free(newpreload);
			}
			else
			{
				envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
			}
		}
	}
	
    int retval = posix_spawn(pid, path, file_actions, attrp, argv, envc);
    envbuf_free(envc);
    return retval;
}
