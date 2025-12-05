
#include <Foundation/Foundation.h>
#include <roothide.h>
#include <sandbox.h>
#include <spawn.h>
#include "assert.h"
#include "bootstrapd.h"
#include "libbsd.h"
#include "ipc.h"

extern const char** environ;

#define BSD_PID_PATH jbroot("/basebin/.bootstrapd.pid")


NSString* gSandboxExtensions = nil;
NSString* gSandboxExtensionsExt = nil;

NSString *generateSandboxExtensions(BOOL ext)
{
	NSMutableString *extensionString = [NSMutableString new];

	char jbrootbase[PATH_MAX];
	char jbrootsecondary[PATH_MAX];
	snprintf(jbrootbase, sizeof(jbrootbase), "/private/var/containers/Bundle/Application/.jbroot-%016llX/", jbrand());
	snprintf(jbrootsecondary, sizeof(jbrootsecondary), "/private/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX/", jbrand());

	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.app-sandbox.read", jbrootbase, 0)]];
	[extensionString appendString:@"|"];
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootbase, 0)]];
	[extensionString appendString:@"|"];

	char* class = ext ? "com.apple.app-sandbox.read-write" : "com.apple.app-sandbox.read";
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file(class, jbrootsecondary, 0)]];
	[extensionString appendString:@"|"];
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootsecondary, 0)]];
	//[extensionString appendString:@"|"];

	return extensionString;
}

int handleRequest(int conn, pid_t pid, int reqId, NSDictionary* msg)
{
    NSLog(@"handleRequest %d from %d : %@", reqId, pid, msg);

	switch(reqId)
	{
		case BSD_REQ_ENABLE_JIT:
		{
			int result = 0;
			if(pid > 0) {
				int enableJIT(pid_t);
				result = enableJIT(pid);
			} else {
				result = -1;
			}

			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_ENABLE_JIT2:
		{
			int result = 0;
			pid_t _pid = [msg[@"pid"] intValue];
			NSLog(@"BSD_REQ_ENABLE_JIT2 %d -> %d", pid, _pid);
			if(_pid > 0) {
				int enableJIT(pid_t);
				result = enableJIT(_pid);
			} else {
				result = -1;
			}

			reply(conn, @{@"result": @(result)});
		} break;

		case BSD_REQ_GET_SBTOKEN:
		{
			reply(conn, @{@"result": @(0), @"sbtoken":gSandboxExtensions});
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
			NSLog(@"unknow request!");
			reply(conn, nil);
			abort();
			break;

	}

	return 0;
}


int jitest(int count, int time)
{
	for(int i=0; i<count; i++)
	{
		if(time) usleep(time);

		NSLog(@"test %d", i);

		bsd_enableJIT();
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
_daemon(nochdir, noclose)
	int nochdir, noclose;
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


int stopServer(bool force)
{
	int result = -1;
	FILE* fp = fopen(BSD_PID_PATH, "r");
	if(fp) {
		pid_t pid=0;
		fscanf(fp, "%d", &pid);
		NSLog(@"server pid=%d", pid);
		if(pid > 0) {

			result = bsd_stopServer();
				
			if(force) {
				sleep(1);
				kill(pid, SIGKILL);
				NSLog(@"kill status=%d", result);
				unlink(BSD_PID_PATH);
			}
		}
		fclose(fp);
	} else {
		NSLog(@"server not running!");
	}
	return result;
}

void sigtest(int signo) {
	NSLog(@"signo=%d", signo);
}

int start_run_server()
{
	if(getpid()==getpgrp()) {
		//from theos install.exec
		sigignore(SIGPIPE); //break by theos->ssh
	} else {
		ASSERT(_daemon(0,0)==0);
	}

	gSandboxExtensions = generateSandboxExtensions(NO);
	gSandboxExtensionsExt = generateSandboxExtensions(YES);

	int ret = run_ipc_server(handleRequest);
	NSLog(@"server return");
	unlink(BSD_PID_PATH);

	return ret;
}


#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);


int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		NSLog(@"Hello bootstrapd! pid=%d, uid=%d\n", getpid(), getuid());
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
							NSLog(@"server is running (%d)", pid);
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
			else if(strcmp(argv[1], "check") == 0)
			{
				int result=-1;
				FILE* fp = fopen(BSD_PID_PATH, "r");
				if(fp) {
					pid_t pid=0;
					fscanf(fp, "%d", &pid);
					NSLog(@"server pid=%d", pid);
					if(pid > 0) {
						result = kill(pid, 0);
						NSLog(@"server status=%d", result);
					}
					fclose(fp);
				} else {
					NSLog(@"server not running!");
				}
				return result;
			}
			else if(strcmp(argv[1], "stop") == 0)
			{
				bool force = argc>=3 && strcmp(argv[2],"-f")==0;
				return stopServer(force);
			}
			else if(strcmp(argv[1], "jitest") == 0)
			{
				int count=1; int time=0;
				if(argc >= 3) count = atoi(argv[2]);
				if(argc >= 4) time = atoi(argv[3]);
				jitest(count, time);
				NSLog(@"client return!\n");
			}
			else if(strcmp(argv[1], "usreboot") == 0)
			{
				int userspaceReboot(void);
				userspaceReboot();
			}
			else if(strcmp(argv[1], "openssh") == 0)
			{
				ASSERT(argc >= 3);
				if(strcmp(argv[2],"start")==0) {
					return bsd_opensshctl(true);
				} else if(strcmp(argv[2],"stop")==0) {
					return bsd_opensshctl(false);
				} else if(strcmp(argv[2],"check")==0) {
					return bsd_opensshcheck();
				} else abort();
			}
			else if(strcmp(argv[1], "sbtoken") == 0)
			{
				NSLog(@"sbtoken=%s", bsd_getsbtoken());
			}
			else {
				printf("unknown command\n");
				abort();
			}
		}

		return 0;
	}
}
