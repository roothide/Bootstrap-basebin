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


// Derived from posix_spawnp in Apple libc
int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path))
{
	const char *env_path;
	char *bp;
	char *cur;
	char *p;
	char **memp;
	int lp;
	int ln;
	int cnt;
	int err = 0;
	int eacces = 0;
	struct stat sb;
	char path_buf[PATH_MAX];

	env_path = searchPath;
	if (!env_path) {
		env_path = getenv("PATH");
		if (!env_path) {
			env_path = _PATH_DEFPATH;
		}
	}

	/* If it's an absolute or relative path name, it's easy. */
	if (index(file, '/')) {
		bp = (char *)file;
		cur = NULL;
		goto retry;
	}
	bp = path_buf;

	/* If it's an empty path name, fail in the usual POSIX way. */
	if (*file == '\0')
		return (ENOENT);

	if ((cur = alloca(strlen(env_path) + 1)) == NULL)
		return ENOMEM;
	strcpy(cur, env_path);
	while ((p = strsep(&cur, ":")) != NULL) {
		/*
		 * It's a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		if (*p == '\0') {
			p = ".";
			lp = 1;
		} else {
			lp = strlen(p);
		}
		ln = strlen(file);

		/*
		 * If the path is too long complain.  This is a possible
		 * security issue; given a way to make the path too long
		 * the user may spawn the wrong program.
		 */
		if (lp + ln + 2 > sizeof(path_buf)) {
			err = ENAMETOOLONG;
			goto done;
		}
		bcopy(p, path_buf, lp);
		path_buf[lp] = '/';
		bcopy(file, path_buf + lp + 1, ln);
		path_buf[lp + ln + 1] = '\0';

retry:		err = attemptHandler(bp);
		switch (err) {
		case E2BIG:
		case ENOMEM:
		case ETXTBSY:
			goto done;
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
		case ENOTDIR:
			break;
		case ENOEXEC:
			goto done;
		default:
			/*
			 * EACCES may be for an inaccessible directory or
			 * a non-executable file.  Call stat() to decide
			 * which.  This also handles ambiguities for EFAULT
			 * and EIO, and undocumented errors like ESTALE.
			 * We hope that the race for a stat() is unimportant.
			 */
			if (stat(bp, &sb) != 0)
				break;
			if (err == EACCES) {
				eacces = 1;
				continue;
			}
			goto done;
		}
	}
	if (eacces)
		err = EACCES;
	else
		err = ENOENT;
done:
	return (err);
}

void enumeratePathString(const char *pathsString, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *pathsCopy = strdup(pathsString);
	char *pathString = strtok(pathsCopy, ":");
	while (pathString != NULL) {
		bool stop = false;
		enumBlock(pathString, &stop);
		if (stop) break;
		pathString = strtok(NULL, ":");
	}
	free(pathsCopy);
}

// extern const char* bootstrapath;
int posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
    const char* preload = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
    char **envc = envbuf_mutcopy((const char **)envp);

	bool isBootstrapApp = stringEndsWith(path, "/Bootstrap.app/Bootstrap");

	const char* bootstrapath = jbroot("/basebin/bootstrap.dylib");
    if(!isBootstrapApp) if(!preload || !strstr(preload, "/basebin/bootstrap.dylib"))
    {
        int newlen = strlen(bootstrapath)+1;
        if(preload) newlen += strlen(preload) + 1;

        char newpreload[newlen];
        strcpy(newpreload, bootstrapath);

        if(preload) {
            strcat(newpreload, ":");
            strcat(newpreload, preload);
        }

        envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newpreload, 1);
    }
	
    int retval = posix_spawn(pid, path, file_actions, attrp, argv, envc);
    envbuf_free(envc);
    return retval;
}
