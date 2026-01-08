#include "commlib.h"

void (*CommLogFunction)(const char* format, ...);
void (*CommErrFunction)(const char* format, ...);

#define SYSLOG(...) do { if(CommLogFunction)CommLogFunction(__VA_ARGS__); } while(0)
#define SYSERR(...) do { if(CommErrFunction)CommErrFunction(__VA_ARGS__); } while(0)
