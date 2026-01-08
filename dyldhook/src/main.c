#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <errno.h>
#include "dyld.h"

void* DYLD_REAL_ENTRY = NULL;

__attribute__((section("__DATA,__all_image_info"))) char __all_image_info[0x4000];

int* __error(void)
{
	static int err = 0;
	return &err;
}
int cerror(int err)
{
	errno = err;
	return -1;
}
__attribute__((naked)) uint64_t msyscall_errno(uint64_t syscall, ...)
{
    asm(
        "mov x16, x0\n"
        "ldp x0, x1, [sp]\n"
        "ldp x2, x3, [sp, 0x10]\n"
        "ldp x4, x5, [sp, 0x20]\n"
        "ldp x6, x7, [sp, 0x30]\n"
        "svc 0x80\n"
        "b.cs 20f\n"
        "ret\n"
        "20:\n"
        "b _cerror\n"
        );
}


static int _simple_memcmp(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return (0);
}

const char *_simple_getenv(const char **envp, char *key)
{
    const char **p;
    size_t var_len;

    var_len = strlen(key);

    for (p = envp; p && *p; p++) {
        size_t p_len = strlen(*p);

        if (p_len >= var_len &&
            _simple_memcmp(*p, key, var_len) == 0 &&
            (*p)[var_len] == '=') {
            return &(*p)[var_len + 1];
        }
    }

    return NULL;
}

struct sandbox_policy_layout {
    void *profile;
    uint64_t len;
    void *container;
    uint64_t containerLen;
    uint64_t pad1;
    uint64_t pad2;
};

int64_t sandbox_extension_consume(const char *extension_token)
{
	int64_t r = 0xAAAAAAAAAAAAAAAA;
	if (!strcmp(extension_token, "invalid")) return 0;

	struct sandbox_policy_layout data = {
		.profile = (void *)extension_token,
		.len = strlen(extension_token) + 1,
		.container = &r,
	};

	if (__sandbox_ms("Sandbox", 6, &data) != 0) {
		return -1;
	}
	else {
		return r;
	}
}

void unsandbox(char *sbtokens)
{
	if (sbtokens[0] == '\0') return;

	char *it = sbtokens;
	char *last = sbtokens;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void* dyldhook_init(uintptr_t kernelParams)
{
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	const char **envp = (const char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));

	const char* sbtoken = _simple_getenv(envp, "__SANDBOX_EXTENSIONS");
	unsandbox((char*)sbtoken);

	return DYLD_REAL_ENTRY;
}
