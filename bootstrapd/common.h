#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"

#ifdef BOOTSTRAPD

#define SYSLOG(...)	NSLog(@ __VA_ARGS__)

#elif DEBUG==1

#include <sys/syslog.h>
extern int ipc_log_enabled;
#define SYSLOG(...) do if(ipc_log_enabled) {\
openlog("bootstrap",LOG_PID,LOG_AUTH);\
syslog(LOG_DEBUG, __VA_ARGS__);closelog();\
} while(0)

#define printf	SYSLOG
#define perror(x) SYSLOG("%s : %s", x, strerror(errno))

#else

#define SYSLOG(...)
#define printf(...)

#endif
