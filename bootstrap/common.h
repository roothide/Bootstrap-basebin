
#include <sys/syslog.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>
#include "commlib.h"

extern char** NXArgv; // __NSGetArgv() not working on ctor
extern int    NXArgc;

extern char* g_executable_path;
extern char* g_sandbox_extensions;

#define EXPORT __attribute__ ((visibility ("default")))

#ifdef DEBUG
extern void bootstrapLog(const char* format, ...);
extern void (*bootstrapLogFunction)(const char* format, ...);
#define SYSLOG(...) do { if(bootstrapLogFunction)bootstrapLogFunction(__VA_ARGS__); } while(0)
#else
#define SYSLOG(...)
#endif

bool string_has_prefix(const char *str, const char* prefix);
bool string_has_suffix(const char* str, const char* suffix);

void fixsuid();

extern struct mach_header_64* _dyld_get_prog_image_header();
extern intptr_t _dyld_get_image_slide(struct mach_header_64* mh);


extern int posix_spawn_hook(pid_t *restrict pid, const char *restrict file,
					   const posix_spawn_file_actions_t *restrict file_actions,
					    posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict]);

                       