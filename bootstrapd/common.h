#include "commlib.h"

#ifdef ENABLE_LOGS
#define SYSLOG(...)	do { NSLog(@ __VA_ARGS__); FileLogDebug(__VA_ARGS__); } while(0)
#else
#define SYSLOG(...)	do { NSLog(@ __VA_ARGS__); } while(0)
#endif