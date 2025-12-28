#include "commlib.h"

void (*CommLogFunction)(const char* format, ...);

#define SYSLOG(...) do { if(CommLogFunction)CommLogFunction(__VA_ARGS__); } while(0)
