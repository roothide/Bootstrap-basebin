#include <roothide.h>

#define BSD_PID_PATH jbroot("/basebin/.bootstrapd.pid")

enum bootstrapReq
{
	BSD_REQ_NONE,
	BSD_REQ_CHECK_SERVER,
	BSD_REQ_STOP_SERVER,
	BSD_REQ_GET_SBTOKEN,
	BSD_REQ_ENABLE_JIT,
	BSD_REQ_ENABLE_JIT2,
	BSD_REQ_SSH_CHECK,
	BSD_REQ_SSH_START,
	BSD_REQ_SSH_STOP,
	BSD_REQ_VAR_CLEAN,
	BSD_REQ_MAX_REQ
};

bool bsd_tick_mach_service();

int bsd_enableJIT();
int bsd_enableJIT2(pid_t pid);

const char* bsd_getsbtoken();

int bsd_opensshcheck();
int bsd_opensshctl(bool run);

int bsd_checkServer();
int bsd_stopServer();

int bsd_varClean();
