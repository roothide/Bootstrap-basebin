#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <roothide.h>

#include "commlib.h"

int main(int argc, char *argv[]) {

	// FILE* fp = fopen("/var/log/launchd.log", "w+");
	// if (fp) {
	//     fprintf(fp, "launchd started args:\n");
	//     for (int i = 0; i < argc; i++) {
	//         fprintf(fp, "%s\n", argv[i]);
	//     }
	//     fflush(fp);
	//     fprintf(fp, "launchd started with environment variables:\n");
	//     for (char **env = environ; *env != 0; env++) {
	//         fprintf(fp, "%s\n", *env);
	//     }
	//     fflush(fp);
	//     fprintf(fp, "jbroot: %s\n", jbroot("/"));
	//     fclose(fp);
	// }

	setenv("DYLD_INSERT_LIBRARIES", jbroot("/basebin/launchdhook.dylib"), 1);

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	if (__builtin_available(iOS 16.0, *)) {
		posix_spawnattr_set_launch_type_np(&attr, 0);
	}

	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC|POSIX_SPAWN_CLOEXEC_DEFAULT);

	return posix_spawn(NULL, jbroot("/.sysroot/sbin/launchd"), NULL, &attr, argv, environ);
}
