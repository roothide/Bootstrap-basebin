#include <private/bsm/audit.h>
#include <Foundation/Foundation.h>
#include <roothide.h>
#include <codesign.h>
#include <dlfcn.h>
#include "common.h"
#include "fishhook.h"
#include "dobby.h"
#include "jbclient.h"

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

    SYSLOG("csops(ops=%d,pid=%d) ret=(%d,err=%d) : data=%08X size=%lx", ops, pid, ret,ret?errno:0, useraddr ? *(uint32_t*)useraddr : 0, usersize);

	if(ops==CS_OPS_STATUS && useraddr) 
    {
        uint32_t csflags = *(uint32_t*)useraddr;
        if(ret == 0)
        {
            if((csflags & CS_PLATFORM_BINARY) == 0)
            {
                if(pid!=getpid() && launchctl_support() && jbclient_blacklist_check_pid(pid)) {
                    SYSLOG("csops_audittoken: skip blacklisted pid=%d", pid);
                    return ret;
                }

                *(uint32_t*)useraddr |= CS_VALID;
                *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
                *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
            }

        } else {
            SYSLOG("csops_audittoken(CS_OPS_STATUS) failed? pid=%d,pidversion=%d", pid, proc_get_pidversion(pid));
            //*(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
        }
	}

	return ret;
}

int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int new_csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token)
{
    int ret = orig_csops_audittoken(pid, ops, useraddr, usersize, token);

    SYSLOG("csops_audittoken(ops=%d,pid=%d) ret=(%d,err=%d) : data=%08X size=%lx token=%p", ops, pid, ret,ret?errno:0, useraddr ? *(uint32_t*)useraddr : 0, usersize, token);

	if(ops==CS_OPS_STATUS && useraddr) 
    {
        uint32_t csflags = *(uint32_t*)useraddr;
        if(ret == 0)
        {
            if((csflags & CS_PLATFORM_BINARY) == 0)
            {
                if(pid!=getpid() && launchctl_support() && jbclient_blacklist_check_pid(pid)) {
                    SYSLOG("csops_audittoken: skip blacklisted pid=%d", pid);
                    return ret;
                }

                *(uint32_t*)useraddr |= CS_VALID;
                *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
                *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
            }

        } else {
            extern int audit_token_to_pidversion(audit_token_t atoken);
            SYSLOG("csops_audittoken(CS_OPS_STATUS) failed? pid=%d,pidversion=%d token=%p/%d/%d", pid, proc_get_pidversion(pid),
                   token,  token ? audit_token_to_pid(*token) : -1, token ? audit_token_to_pidversion(*token) : -1);
            //*(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
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

#include <sys/proc_info.h>
#define PROC_INFO_CALL_PIDINFO           0x2
int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void * buffer, int buffersize);
int (*orig__proc_info)(int callnum, int pid, int flavor, uint64_t arg, void * buffer, int buffersize);
int new__proc_info(int callnum, int pid, int flavor, uint64_t arg, void * buffer, int buffersize)
{
    int ret = orig__proc_info(callnum, pid, flavor, arg, buffer, buffersize);
    SYSLOG("__proc_info(callnum=%d,pid=%d,flavor=%d,arg=%llx) ret=(%d,err=%d)", callnum, pid, flavor, arg, ret, ret?errno:0);
    
    if(callnum == PROC_INFO_CALL_PIDINFO && flavor == PROC_PIDPATHINFO) {
        if(ret == 0) {
            SYSLOG("__proc_info PROC_PIDPATHINFO: %s", (char*)buffer);
            SYSLOG("callstack=%@", [NSThread callStackSymbols]);
            const char* path = rootfs((char*)buffer);
            if(string_has_prefix(path, "/.sysroot/")) {
                strlcpy((char*)buffer, path + sizeof("/.sysroot")-1, buffersize);
                SYSLOG("__proc_info PROC_PIDPATHINFO fixed: %s", (char*)buffer);
            }
        }
    }

    return ret;
}
int __proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor, uint32_t flags, uint64_t ext_id, uint64_t arg, user_addr_t buffer, int32_t buffersize);
int (*orig__proc_info_extended_id)(int32_t callnum, int32_t pid, uint32_t flavor, uint32_t flags, uint64_t ext_id, uint64_t arg, user_addr_t buffer, int32_t buffersize);
int new__proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor, uint32_t flags, uint64_t ext_id, uint64_t arg, user_addr_t buffer, int32_t buffersize)
{
    int ret = orig__proc_info_extended_id(callnum, pid, flavor, flags, ext_id, arg, buffer, buffersize);

    SYSLOG("__proc_info_extended_id(callnum=%d,pid=%d,flavor=%d,flags=%x,ext_id=%llx,arg=%llx) ret=(%d,err=%d)", callnum, pid, flavor, flags, ext_id, arg, ret, ret?errno:0);

    if(callnum == PROC_INFO_CALL_PIDINFO && flavor == PROC_PIDPATHINFO) {
        if(ret == 0) {
            SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO: %s", (char*)buffer);
            SYSLOG("callstack=%@", [NSThread callStackSymbols]);
            const char* path = rootfs((char*)buffer);
            if(string_has_prefix(path, "/.sysroot/")) {
                strlcpy((char*)buffer, path + sizeof("/.sysroot")-1, buffersize);
                SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO fixed: %s", (char*)buffer);
            }
        }
    }

    return ret;
}

void init_process_path_hook()
{
    SYSLOG("init_process_path_hook %d", getpid());

    if(requireJIT()!=0) return;

    DobbyHook(__proc_info, new__proc_info, (void**)&orig__proc_info);
    DobbyHook(__proc_info_extended_id, new__proc_info_extended_id, (void**)&orig__proc_info_extended_id);

    char**_CFGetProcessPath();
    SYSLOG("_CFGetProcessPath = %s", *_CFGetProcessPath());
    SYSLOG("NSBundle.mainBundle.executablePath = %@", NSBundle.mainBundle.executablePath);
    SYSLOG("NSProcessInfo.processInfo.arguments = %@", NSProcessInfo.processInfo.arguments);
    SYSLOG("dyld_image_path_containing_address = %s", dyld_image_path_containing_address(_dyld_get_prog_image_header()));
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
