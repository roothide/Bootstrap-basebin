
#include <Foundation/Foundation.h>
#include <roothide.h>
#include <sandbox.h>
#include <spawn.h>
#include "bootstrapd.h"
#include "libbsd.h"
#include "ipc.h"

extern const char** environ;

#define BSD_PID_PATH jbroot("/basebin/.bootstrapd.pid")


struct proc_bsdinfo {
	uint32_t                pbi_flags;              /* 64bit; emulated etc */
	uint32_t                pbi_status;
	uint32_t                pbi_xstatus;
	uint32_t                pbi_pid;
	uint32_t                pbi_ppid;
	uid_t                   pbi_uid;
	gid_t                   pbi_gid;
	uid_t                   pbi_ruid;
	gid_t                   pbi_rgid;
	uid_t                   pbi_svuid;
	gid_t                   pbi_svgid;
	uint32_t                rfu_1;                  /* reserved */
	char                    pbi_comm[MAXCOMLEN];
	char                    pbi_name[2 * MAXCOMLEN];  /* empty if no name is registered */
	uint32_t                pbi_nfiles;
	uint32_t                pbi_pgid;
	uint32_t                pbi_pjobc;
	uint32_t                e_tdev;                 /* controlling tty dev */
	uint32_t                e_tpgid;                /* tty process group id */
	int32_t                 pbi_nice;
	uint64_t                pbi_start_tvsec;
	uint64_t                pbi_start_tvusec;
};

#define PROC_PIDTBSDINFO                3
#define PROC_PIDTBSDINFO_SIZE           (sizeof(struct proc_bsdinfo))

int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

pid_t getpppid()
{
    struct proc_bsdinfo procInfo;
	if (proc_pidinfo(getppid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0) {
		return -1;
	}
    return procInfo.pbi_ppid;
}


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

int start_run_server()
{
	gSandboxExtensions = generateSandboxExtensions(NO);
	gSandboxExtensionsExt = generateSandboxExtensions(YES);

	int ret = start_ipc_server(handleRequest);
	NSLog(@"server return");
	unlink(BSD_PID_PATH);

	return ret;
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		NSLog(@"Hello bootstrapd! pid=%d, uid=%d\n", getpid(), getuid());
		printf("Hello bootstrapd! pid=%d, uid=%d\n", getpid(), getuid());

		if(argc >= 2) 
		{
			if(strcmp(argv[1], "daemon") == 0) {
				_daemon(0,0);
				argv[1] = "server";
    			return posix_spawn(NULL, argv[0], NULL, NULL, argv, envp);
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
								assert(stopServer(true)==0);
							} else {
								return -1;
							}
						}
					}
					fclose(fp);
				}

				 fp = fopen(BSD_PID_PATH, "w");
				assert(fp != NULL);
				fprintf(fp, "%d", getpid());
				fclose(fp);

				return start_run_server();
			}
			else if(strcmp(argv[1], "check") == 0)
			{
				FILE* fp = fopen(BSD_PID_PATH, "r");
				if(fp) {
					pid_t pid=0;
					fscanf(fp, "%d", &pid);
					NSLog(@"server pid=%d", pid);
					if(pid > 0) {
						int killed = kill(pid, 0);
						NSLog(@"server status=%d", killed);
					}
					fclose(fp);
				} else {
					NSLog(@"server not running!");
				}
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
				assert(argc >= 3);
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
			else if(strcmp(argv[1], "unrestrict") == 0)
			{
				assert(argv[2] != NULL);
				int realstore(char* path);
				return realstore(argv[2]);
			}
		}

		return 0;
	}
}
