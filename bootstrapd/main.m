
#include <Foundation/Foundation.h>
#include <roothide.h>
#include <spawn.h>
#include "common.h"
#include "libbsd.h"
#include "ipc.h"

const char* g_sandbox_extensions = NULL;
const char* g_sandbox_extensions_ext = NULL;

int handleRequest(int conn, pid_t pid, int reqId, NSDictionary* msg)
{
    SYSLOG("handleRequest %d from %d : %s", reqId, pid, msg.debugDescription.UTF8String);

	switch(reqId)
	{
		case BSD_REQ_ENABLE_JIT:
		{
			int result = 0;
			if(pid > 0) {
				result = proc_enable_jit(pid, false);
			} else {
				result = -1;
			}

			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_ENABLE_JIT2:
		{
			int result = 0;
			pid_t _pid = [msg[@"pid"] intValue];
			SYSLOG("BSD_REQ_ENABLE_JIT2 %d -> %d", pid, _pid);
			if(_pid > 0) {
				result = proc_enable_jit(_pid, false);
			} else {
				result = -1;
			}

			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_GET_SBTOKEN:
		{
			reply(conn, @{@"result": @(0), @"sbtoken":@(g_sandbox_extensions)});
		} break;

		case BSD_REQ_CHECK_SERVER:
		{
			reply(conn, @{@"result": @(0)});
		} break;

		case BSD_REQ_STOP_SERVER:
		{
			int result = set_stop_server();
			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_SSH_START:
		{
			int openssh_start();
			int result = openssh_start();
			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_SSH_CHECK:
		{
			int openssh_check();
			int result = openssh_check();
			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_SSH_STOP:
		{
			int openssh_stop();
			int result = openssh_stop();
			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_VAR_CLEAN:
		{
			NSString* bundleIdentifier = msg[@"bundleIdentifier"];
			int varClean(NSString* bundleIdentifier);
			int result = varClean(bundleIdentifier);

			reply(conn, @{@"result": @(result)});
		} break;

		default:
			SYSLOG("unknow request!");
			reply(conn, nil);
			abort();
			break;

	}

	return 0;
}

#define _dup2 dup2
#define _open open
#define _close close
#define _sigaction sigaction
#include <paths.h>
#include <fcntl.h>
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
	// move_to_root_bootstrap();
#endif /* !VARIANT_PRE1050 */
	// switch (fork()) {
	// case -1:
	// 	return (-1);
	// case 0:
	// 	break;
	// default:
	// 	_exit(0);
	// }

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

int start_run_server()
{
	if(getpid()==getpgrp()) {
		//from theos install.exec
		sigignore(SIGPIPE); //break by theos->ssh
	} else {
		ASSERT(_daemon(0,0)==0);
	}

	void varclean_init(void);
	 varclean_init();

	g_sandbox_extensions = generate_sandbox_extensions(false);
	g_sandbox_extensions_ext = generate_sandbox_extensions(true);

	int ret = run_ipc_server(handleRequest);
	SYSLOG("server return");
	unlink(BSD_PID_PATH);

	return ret;
}

int stopServer(bool force)
{
	int result = -1;
	FILE* fp = fopen(BSD_PID_PATH, "r");
	if(fp) {
		pid_t pid=0;
		fscanf(fp, "%d", &pid);
		SYSLOG("server pid=%d", pid);
		if(pid > 0) {

			result = bsd_stopServer();
				
			if(force) {
				sleep(1);
				kill(pid, SIGKILL);
				SYSLOG("kill status=%d", result);
				unlink(BSD_PID_PATH);
			}
		}
		fclose(fp);
	} else {
		SYSLOG("server not running!");
	}
	return result;
}

void CommLog(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
	char* logbuf = NULL;
	vasprintf(&logbuf, format, ap);
	SYSLOG("%s", logbuf);
	free(logbuf);
    va_end(ap);
}

int main(int argc, char *argv[], char *envp[]) {

	enableCommLog(CommLog, CommLog);

	@autoreleasepool {
		SYSLOG("Hello bootstrapd! pid=%d, uid=%d\n", getpid(), getuid());
		printf("Hello bootstrapd! pid=%d, uid=%d\n", getpid(), getuid());

		if(argc >= 2) 
		{
			if(strcmp(argv[1], "daemon") == 0) {
				argv[1] = "server";

				posix_spawnattr_t attr;
				posix_spawnattr_init(&attr);

				posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
				posix_spawnattr_set_persona_uid_np(&attr, 0);
				posix_spawnattr_set_persona_gid_np(&attr, 0);

				return posix_spawn(NULL, argv[0], NULL, &attr, argv, envp);
			}
			else if(strcmp(argv[1], "server") == 0)
			{
				bool force = argc>=3 && strcmp(argv[2],"-f")==0;

				FILE* fp = fopen(BSD_PID_PATH, "r");
				if(fp) {
					pid_t pid=0;
					fscanf(fp, "%d", &pid);
					if(pid > 0) {
						int killed = kill(pid, 0);
						if(killed==0) {
							SYSLOG("server is running (%d)", pid);
							if(force) {
								ASSERT(stopServer(true)==0);
							} else {
								return -1;
							}
						}
					}
					fclose(fp);
				}

				fp = fopen(BSD_PID_PATH, "w");
				ASSERT(fp != NULL);
				fprintf(fp, "%d", getpid());
				fclose(fp);
				return start_run_server();
			}
		}

		printf("bootstrapd cannot be run directly.\n");
		return -1;
	}
}
