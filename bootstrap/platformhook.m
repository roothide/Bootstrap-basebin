#include <Foundation/Foundation.h>
#include <roothide.h>
#include <codesign.h>
#include <dlfcn.h>
#include "common.h"
#include "fishhook.h"
#include "dobby.h"

bool os_variant_has_internal_content();
bool (*orig_os_variant_has_internal_content)();
bool new_os_variant_has_internal_content()
{
    return true;
}

int (*orig_csops)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize) = csops;
int new_csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize)
{
	int ret = orig_csops(pid, ops, useraddr, usersize);

    SYSLOG("csops(ops=%d) ret=(%d,err=%d) : pid=%d data=%08X size=%lx", ops, ret,errno, pid, useraddr ? *(uint32_t*)useraddr : 0, usersize);

	if(ops==CS_OPS_STATUS && useraddr) 
    {
        if(ret == 0) {
            *(uint32_t*)useraddr |= CS_VALID;
            *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
            *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
        } else {
            *(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
        }
	}

	return ret;
}

int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int new_csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token)
{
    int ret = orig_csops_audittoken(pid, ops, useraddr, usersize, token);

    SYSLOG("csops_audittoken(ops=%d) ret=(%d,err=%d) : pid=%d data=%08X size=%lx token=%p", ops, ret,errno, pid, useraddr ? *(uint32_t*)useraddr : 0, usersize, token);

	if(ops==CS_OPS_STATUS && useraddr) 
    {
        if(ret == 0) {
            *(uint32_t*)useraddr |= CS_VALID;
            *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
            *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
        } else {
            *(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
        }
	}

    return ret;
}

void init_platformHook()
{    
    SYSLOG("init_platformHook %d", getpid());

    if(requireJIT()!=0) return;
    
    DobbyHook(csops, new_csops, (void**)&orig_csops);
    DobbyHook(csops_audittoken, new_csops_audittoken, (void**)&orig_csops_audittoken);
    // DobbyHook(os_variant_has_internal_content, new_os_variant_has_internal_content, (void**)&orig_os_variant_has_internal_content);
}


#include <bootstrap.h>
int (*orig__xpc_activate_endpoint)(const char *name, int type, void* handle, uint64_t flags, mach_port_t* p_port, bool* non_launching);
int new__xpc_activate_endpoint(const char *name, int type, void* handle, uint64_t flags, mach_port_t* p_port, bool* p_non_launching)
{
    SYSLOG("_xpc_activate_endpoint name=%s type=%d handle=%p flags=%llx", name, type, handle, flags);

    int ret = orig__xpc_activate_endpoint(name, type, handle, flags, p_port, p_non_launching);
    SYSLOG("_xpc_activate_endpoint ret=%d port=%x non-launching=%d", ret, *p_port, *p_non_launching);

    if(ret != 0) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_check_in(bootstrap_port, name, &port);
        SYSLOG("bootstrap_check_in port=%x kr=%x,%s", port, kr, bootstrap_strerror(kr));
        if(kr == KERN_SUCCESS) {
            *p_non_launching = false;
            *p_port = port;
            ret = 0;
        }
    }

    return ret;
}

void init_xpchook()
{
    SYSLOG("init_xpchook %d", getpid());

    if(requireJIT()!=0) return;

    if(dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW)==NULL) {
        SYSLOG("dlopen libxpc.dylib failed");
        return;
    }

    void* _xpc_activate_endpoint = DobbySymbolResolver("/usr/lib/system/libxpc.dylib", "__xpc_activate_endpoint");
    SYSLOG("_xpc_activate_endpoint=%p", _xpc_activate_endpoint);

    DobbyHook(_xpc_activate_endpoint, (void *)new__xpc_activate_endpoint, (void **)&orig__xpc_activate_endpoint);
}
