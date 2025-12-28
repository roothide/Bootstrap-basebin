#include "commlib.h"

#define SYSLOG(...)	do { NSLog(@ __VA_ARGS__); FileLogDebug(__VA_ARGS__); } while(0)
