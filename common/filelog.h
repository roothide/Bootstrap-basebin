// #define ENABLE_LOGS

#ifdef ENABLE_LOGS
#include <unistd.h>
#include <stdbool.h>
#include <sys/syslimits.h>

#define FILELOG_FULL_SYNC 0
#define FILELOG_FORCE_LOG 1

bool FileLogEnabled();
void FileLogDebugFunction(const char *format, ...);
void FileLogErrorFunction(const char *format, ...);

char* FileLogGetLogFilePath(const char* logname, const char* suffix, char buffer[PATH_MAX]);
void FileLogFunction(const char* path, pid_t pid, uint64_t tid, const char* prefix, const char *format, ...);

#define FileLogDebug(...) do { if(FILELOG_FORCE_LOG || FileLogEnabled()) FileLogDebugFunction(__VA_ARGS__); } while(0)
#define FileLogError(...) do { if(FILELOG_FORCE_LOG || FileLogEnabled()) FileLogErrorFunction(__VA_ARGS__); } while(0)

#else
#define FileLogDebug(...)
#define FileLogError(...)
#endif
