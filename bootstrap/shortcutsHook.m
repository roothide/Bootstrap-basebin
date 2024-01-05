#include <Foundation/Foundation.h>
#include <roothide.h>
#include "common.h"
#include "fishhook.h"
#include "dobby.h"

bool os_variant_has_internal_content();
bool (*orig_os_variant_has_internal_content)();
bool new_os_variant_has_internal_content()
{
    return true;
}

#define	CS_OPS_STATUS		0	/* return status */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
int csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int new_csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token)
{
    int ret = orig_csops_audittoken(pid,ops,useraddr,usersize,token);

    if(ops==CS_OPS_STATUS) {
        NSLog(@"csops_audittoken: %d %08X", ret, *(uint32_t*)useraddr);
        *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
    }

    return ret;
}

void init_shortcutsHook()
{    
    NSLog(@"init_shortcutsHook %d", getpid());

    if(requireJIT()!=0) return;
    
    DobbyHook(csops_audittoken, new_csops_audittoken, (void**)&orig_csops_audittoken);
    // DobbyHook(os_variant_has_internal_content, new_os_variant_has_internal_content, (void**)&orig_os_variant_has_internal_content);
}
