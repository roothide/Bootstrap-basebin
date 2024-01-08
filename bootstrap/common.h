
#include <sys/syslog.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>

#define SIGABRT 6
#define OS_REASON_SIGNAL        2
#define OS_REASON_DYLD          6
#define DYLD_EXIT_REASON_OTHER                  9
void abort_with_payload(uint32_t reason_namespace, uint64_t reason_code, 
	void *payload, uint32_t payload_size, 
	const char *reason_string, uint64_t reason_flags) 
	__attribute__((noreturn, cold));

#define	ASSERT(e)	(__builtin_expect(!(e), 0) ?\
 ((void)printf ("%s:%d: failed ASSERTion `%s'\n", __FILE_NAME__, __LINE__, #e),\
 abort_with_payload(OS_REASON_DYLD,DYLD_EXIT_REASON_OTHER,NULL,0, #e, 0)) : (void)0)

extern char** environ;

extern char** NXArgv; // __NSGetArgv() not working on ctor
extern int    NXArgc;

#define EXPORT __attribute__ ((visibility ("default")))

#include <sys/syslog.h>
#define SYSLOG(...) do {\
openlog("bootstrap",LOG_PID,LOG_AUTH);\
syslog(LOG_DEBUG, __VA_ARGS__);closelog();\
} while(0)

bool stringStartsWith(const char *str, const char* prefix);
bool stringEndsWith(const char* str, const char* suffix);

void fixsuid();

int requireJIT();

extern struct mach_header_64* _dyld_get_prog_image_header();
extern intptr_t _dyld_get_image_slide(struct mach_header_64* mh);


extern int posix_spawn_hook(pid_t *restrict pid, const char *restrict file,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict]);

                       