
#include <Foundation/Foundation.h>
#include <roothide.h>
#include "commlib.h"
#include "libbsd.h"

int jitest(int count, int time)
{
	for(int i=0; i<count; i++)
	{
		if(time) usleep(time);

		printf("test %d\n", i);

		assert(bsd_enableJIT() == 0);
	}

	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
#ifdef ENABLE_LOGS
	FileLogDebug("bsctl started args:\n");
	for (int i = 0; i < argc; i++) {
		FileLogDebug("%s\n", argv[i]);
	}
	FileLogDebug("bsctl started with environment variables:\n");
	for (char*const* env = environ; *env != 0; env++) {
		FileLogDebug("%s\n", *env);
	}
#endif

	if(argc >= 2) 
	{
		if(strcmp(argv[1], "startup")==0)
		{
			int ret1 = spawnBootstrap((char*const[]){"/usr/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons", NULL}, NULL, NULL);
			int ret2 = spawnBootstrap((char*const[]){"/usr/bin/uicache", "-a", NULL}, NULL, NULL);
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
					printf("server status=%d\n", result);
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
	}

	printf("unknown command\n");
	return -1;
}
