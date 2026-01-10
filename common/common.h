#include "commlib.h"

extern void (*CommLogFunction)(const char* format, ...);
extern void (*CommErrFunction)(const char* format, ...);

#define SYSLOG(...) do { if(CommLogFunction)CommLogFunction(__VA_ARGS__); } while(0)
#define SYSERR(...) do { if(CommErrFunction)CommErrFunction(__VA_ARGS__); } while(0)
