
#include <Foundation/Foundation.h>
#include <roothide.h>
#include "commlib.h"
#include "libbsd.h"
#include "resign.h"

int jitest(int count, int time)
{
	for(int i=0; i<count; i++)
	{
		if(time) usleep(time);

		printf("test %d\n", i);

		assert(bsd_enableJIT(getpid()) == 0);
	}

	return 0;
}

SInt32 CFUserNotificationDisplayAlert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL, CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage, CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle, CFOptionFlags *responseFlags) API_AVAILABLE(ios(3.0));

int main(int argc, char *argv[], char *envp[])
{
#ifdef ENABLE_LOGS
	FileLogDebug("bsctl started with environment variables:\n");
	for (char*const* env = environ; *env != 0; env++) {
		FileLogDebug("%s\n", *env);
	}
	FileLogDebug("bsctl started args:\n");
	for (int i = 0; i < argc; i++) {
		FileLogDebug("%s\n", argv[i]);
	}
#endif

	if(argc >= 2) 
	{
		if(strcmp(argv[1], "startup")==0)
		{
			FileLogDebug("bsctl startup: checking userspace panic ...");
			NSString* watchdogmsg = [NSString stringWithContentsOfFile:jbroot(@"/var/mobile/.watchdogmsg") encoding:NSUTF8StringEncoding error:nil];
			if(watchdogmsg) {
				NSString* panicMessage = [NSString stringWithFormat:@"Bootstrap has protected you from a userspace panic by temporarily disabling tweak injection and triggering a userspace reboot instead. A log is available under Analytics in the Preferences app. You can reenable tweak injection in the settings of Bootstrap app.\n\nPanic message: \n%@", watchdogmsg];
				CFUserNotificationDisplayAlert(0, 2/*kCFUserNotificationCautionAlertLevel*/, NULL, NULL, NULL, CFSTR("Watchdog Timeout"), (__bridge CFStringRef)panicMessage, NULL, NULL, NULL, NULL);
				ASSERT(unlink(jbroot("/var/mobile/.watchdogmsg")) == 0);
			}

			FileLogDebug("bsctl startup: bootstrapping launch daemons ...");
			int ret1 = spawn_bootstrap_binary((char*const[]){"/usr/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons", NULL}, NULL, NULL);

			FileLogDebug("bsctl startup: refreshing jailbroken apps ...");
			int ret2 = spawn_bootstrap_binary((char*const[]){"/usr/bin/uicache", "-a", NULL}, NULL, NULL);

			return (ret1==0 && ret2==0) ? 0 : -1;
		}
		else if(strcmp(argv[1], "check") == 0)
		{
			int result=-1;
			FILE* fp = fopen(BSD_PID_PATH, "r");
			if(fp) {
				pid_t pid=0;
				fscanf(fp, "%d", &pid);
				printf("server pid=%d\n", pid);
				if(pid > 0) {
					result = kill(pid, 0);
					printf("pid status=%d\n", result);
					printf("ipc status=%d\n", bsd_checkServer());
				}
				fclose(fp);
			} else {
				printf("server not running!\n");
			}
			return result;
		}
		else if(strcmp(argv[1], "stop") == 0)
		{
			return bsd_stopServer();
		}
		else if(strcmp(argv[1], "jitest") == 0)
		{
			int count=1; int time=0;
			if(argc >= 3) count = atoi(argv[2]);
			if(argc >= 4) time = atoi(argv[3]);
			jitest(count, time);
			printf("client return!\n");
			return 0;
		}
		else if(strcmp(argv[1], "usreboot") == 0)
		{
			int userspaceReboot(void);
			return userspaceReboot();
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
			const char* sbtoken = bsd_getsbtoken();
			printf("sbtoken=%s\n", sbtoken);
			if(sbtoken) free((void*)sbtoken);
			return sbtoken==NULL?-1:0;
		}
		else if(strcmp(argv[1], "resign") == 0)
		{
			return ResignSystemExecutables();
		}
	}

	printf("unknown command\n");
	return -1;
}
