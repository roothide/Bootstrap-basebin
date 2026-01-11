#include <stdio.h>
#include <stdint.h>

#define SIGABRT 6
#define OS_REASON_SIGNAL        2
#define OS_REASON_DYLD          6
#define DYLD_EXIT_REASON_OTHER                  9

void abort_with_payload(uint32_t reason_namespace, uint64_t reason_code, 
	void *payload, uint32_t payload_size, 
	const char *reason_string, uint64_t reason_flags) 
	__attribute__((noreturn, cold));

#define	ASSERT(e)	(__builtin_expect(!(e), 0) ?\
	((void)fprintf(stderr, "%s:%d: failed ASSERTion `%s'\n", __FILE_NAME__, __LINE__, #e),\
	abort_with_payload(OS_REASON_DYLD,DYLD_EXIT_REASON_OTHER,NULL,0, #e, 0)) : (void)0)

 #define ABORT(...) do { char *message=NULL; asprintf(&message, __VA_ARGS__); \
	((void)fprintf(stderr, "%s:%d: Abort: %s\n", __FILE_NAME__, __LINE__, message),\
	abort_with_payload(OS_REASON_DYLD,DYLD_EXIT_REASON_OTHER,NULL,0, message, 0)); \
	free(message); _exit(0); } while(0)
