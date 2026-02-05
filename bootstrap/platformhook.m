#include <private/bsm/audit.h>
#include <Foundation/Foundation.h>
#include <sys/sysctl.h>
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
                char teamid[255]={0};
                if(!proc_get_teamid(pid, teamid) || strcmp(teamid, "T8ALTGMVXN")!=0) {
                    return ret;
                }

                *(uint32_t*)useraddr |= CS_VALID;
                *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
                *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
            }
            else { //palehide
                *(uint32_t*)useraddr |= CS_VALID;
            }

        } else {
            SYSLOG("new_csops(CS_OPS_STATUS) failed? pid=%d,pidversion=%d", pid, proc_get_pidversion(pid));
            //*(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
            /* a re-signed system executable may not have permission to call csops on other processes.
             In Bootstrap 1.x, we returned fake data with the caller's process via csops(getpid()), 
             but we should add `com.apple.security.exception.process-info` entitlement to the re-signed executable. */
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
                char teamid[255]={0};
                if(!proc_get_teamid(pid, teamid) || strcmp(teamid, "T8ALTGMVXN")!=0) {
                    return ret;
                }

                *(uint32_t*)useraddr |= CS_VALID;
                *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
                *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
            }
            else { //palehide
                *(uint32_t*)useraddr |= CS_VALID;
            }

        } else {
            extern int audit_token_to_pidversion(audit_token_t atoken);
            SYSLOG("csops_audittoken(CS_OPS_STATUS) failed? pid=%d,pidversion=%d token=%p/%d/%d", pid, proc_get_pidversion(pid),
                   token,  token ? audit_token_to_pid(*token) : -1, token ? audit_token_to_pidversion(*token) : -1);
            //*(uint32_t*)useraddr = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID;
            /* a re-signed system executable may not have permission to call csops on other processes.
             In Bootstrap 1.x, we returned fake data with the caller's process via csops(getpid()), 
             but we should add `com.apple.security.exception.process-info` entitlement to the re-signed executable. */
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
    // SYSLOG("__proc_info(callnum=%d,pid=%d,flavor=%d,arg=%llx) ret=(%d,err=%d)", callnum, pid, flavor, arg, ret, ret?errno:0);
    
    if(callnum == PROC_INFO_CALL_PIDINFO && flavor == PROC_PIDPATHINFO) {
        if(ret == 0) {
            SYSLOG("__proc_info PROC_PIDPATHINFO: %s", (char*)buffer);
            // SYSLOG("callstack=%@", [NSThread callStackSymbols]);
            const char* path = rootfs((char*)buffer);
            if(string_has_prefix(path, "/.sysroot/")) {
                strlcpy((char*)buffer, path + sizeof("/.sysroot")-1, buffersize);
                SYSLOG("__proc_info PROC_PIDPATHINFO fixed: %s", (char*)buffer);
            }
            else if(string_has_prefix(path, "/Applications/") && access(path, F_OK)==0) {
                strlcpy((char*)buffer, path, buffersize);
                SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO fixed: %s", (char*)buffer);
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

    // SYSLOG("__proc_info_extended_id(callnum=%d,pid=%d,flavor=%d,flags=%x,ext_id=%llx,arg=%llx) ret=(%d,err=%d)", callnum, pid, flavor, flags, ext_id, arg, ret, ret?errno:0);

    if(callnum == PROC_INFO_CALL_PIDINFO && flavor == PROC_PIDPATHINFO) {
        if(ret == 0) {
            SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO: %s", (char*)buffer);
            // SYSLOG("callstack=%@", [NSThread callStackSymbols]);
            const char* path = rootfs((char*)buffer);
            if(string_has_prefix(path, "/.sysroot/")) {
                strlcpy((char*)buffer, path + sizeof("/.sysroot")-1, buffersize);
                SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO fixed: %s", (char*)buffer);
            }
            else if(string_has_prefix(path, "/Applications/") && access(path, F_OK)==0) {
                strlcpy((char*)buffer, path, buffersize);
                SYSLOG("__proc_info_extended_id PROC_PIDPATHINFO fixed: %s", (char*)buffer);
            }
        }
    }

    return ret;
}

const char* g_fixed_executable_path = NULL;

int (*orig__NSGetExecutablePath)(char* buf, uint32_t* bufsize);
int new__NSGetExecutablePath(char* buf, uint32_t* bufsize)
{
    if(g_fixed_executable_path) 
    {
        *bufsize = strlcpy(buf, g_fixed_executable_path, *bufsize);
        return 0;
    }
    return orig__NSGetExecutablePath(buf, bufsize);
}

#if __arm64__
#define _COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define _COMM_PAGE_TPRO_WRITE_ENABLE (_COMM_PAGE_START_ADDRESS + 0x0D0)
#define _COMM_PAGE_TPRO_WRITE_DISABLE (_COMM_PAGE_START_ADDRESS + 0x0D8)

static bool os_tpro_is_supported(void)
{
	if (*(uint64_t*)_COMM_PAGE_TPRO_WRITE_ENABLE) {
		return true;
	}
	return false;
}

__attribute__((naked)) bool os_thread_self_tpro_is_writeable(void)
{
	__asm__ __volatile__ (
		"mrs             x0, s3_6_c15_c1_5\n"
		"ubfx            x0, x0, #0x24, #1;\n"
		"ret\n"
	);
}

void os_thread_self_restrict_tpro_to_rw(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_ENABLE)
		: "memory", "x0"
	);
	return;
}

void os_thread_self_restrict_tpro_to_ro(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_DISABLE)
		: "memory", "x0"
	);
	return;
}
#endif

extern char*** _NSGetArgv(void);
extern char** _CFGetProcessPath();

void init_process_path_hook()
{
    SYSLOG("init_process_path_hook %d", getpid());

    if(requireJIT()!=0) return;

    const char* exepath = rootfs(g_executable_path);
    if(string_has_prefix(exepath, "/.sysroot/")) {
        g_fixed_executable_path = strdup(exepath + sizeof("/.sysroot")-1);
    }
    else if(string_has_prefix(exepath, "/Applications/") && access(exepath, F_OK)==0) {
        g_fixed_executable_path = strdup(exepath);
    }

    DobbyHook(__proc_info, new__proc_info, (void**)&orig__proc_info);
    DobbyHook(__proc_info_extended_id, new__proc_info_extended_id, (void**)&orig__proc_info_extended_id);

    if(g_fixed_executable_path)
    {
        DobbyHook(_NSGetExecutablePath, new__NSGetExecutablePath, (void**)&orig__NSGetExecutablePath);

        NXArgv[0] = (char*)g_fixed_executable_path;
        (*_NSGetArgv())[0] = (char*)g_fixed_executable_path;
        *_CFGetProcessPath() = (char*)g_fixed_executable_path;

        char args_buffer[4096] = {0};
        size_t args_buffer_size = sizeof(args_buffer);
        ASSERT(sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, getpid() }, 3, args_buffer, &args_buffer_size, NULL, 0)==0);
        SYSLOG("KERN_PROCARGS2: size=%d, argc=%d executable_path=%s", args_buffer_size, *(int*)args_buffer, args_buffer + sizeof(int));

        uint64_t usrstack=0;
        size_t len = sizeof(usrstack);
        ASSERT(sysctlbyname("kern.usrstack64", &usrstack, &len, NULL, 0) == 0);
        char* arg_addr = (char*)(usrstack - (args_buffer_size - sizeof(int)));
        SYSLOG("usrstack=%llx executable_path=%p,%s", usrstack, arg_addr, arg_addr);
        size_t executable_path_length = strlen(arg_addr);
        size_t fixed_executable_path_length = strlen(g_fixed_executable_path);
        ASSERT(executable_path_length >= fixed_executable_path_length);
        ASSERT(is_same_file(arg_addr, g_executable_path));
        memset(arg_addr, 0, executable_path_length);
        strcpy((char*)arg_addr, (char*)g_fixed_executable_path);
        char* arg0 = arg_addr + executable_path_length+1;
        while (*arg0 == 0) arg0++;
        SYSLOG("arg0 = %s", arg0);
        size_t arg0_length = strlen(arg0);
        ASSERT(arg0_length >= fixed_executable_path_length);
        memset(arg0, 0, arg0_length);
        strcpy(arg0+arg0_length-fixed_executable_path_length, (char*)g_fixed_executable_path);

        NSMutableArray* new_arguments = NSProcessInfo.processInfo.arguments.mutableCopy;
        new_arguments[0] = @(g_fixed_executable_path);
        [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:new_arguments];

        bool needsTPRORevert = false;
        if (os_tpro_is_supported()) {
            if (!os_thread_self_tpro_is_writeable()) {
                os_thread_self_restrict_tpro_to_rw();
                needsTPRORevert = true;
            }
        }

        for(int i=0; i<_dyld_image_count(); i++) {
            if((void*)_dyld_get_image_header(i) == (void*)_dyld_get_prog_image_header()) {
                const char* image_path = _dyld_get_image_name(i);
                ASSERT(strlen(image_path) >= strlen(g_fixed_executable_path));
		        if (!__builtin_available(iOS 16.0, *)) {
                    ASSERT(vm_protect(mach_task_self(), (vm_address_t)image_path, strlen(image_path)+1, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)==KERN_SUCCESS);
                }
                strcpy((char*)image_path, (char*)g_fixed_executable_path);
            }
        }

        const char* prog_image_path = dyld_image_path_containing_address(_dyld_get_prog_image_header());
        ASSERT(strlen(prog_image_path) >= strlen(g_fixed_executable_path));
        if (!__builtin_available(iOS 16.0, *)) {
            ASSERT(vm_protect(mach_task_self(), (vm_address_t)prog_image_path, strlen(prog_image_path)+1, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)==KERN_SUCCESS);
        }
        strcpy((char*)prog_image_path, (char*)g_fixed_executable_path);

        if (needsTPRORevert) {
            os_thread_self_restrict_tpro_to_ro();
        }

        uint8_t* __initedMainBundle = DobbySymbolResolver("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", "__initedMainBundle");
        SYSLOG("__initedMainBundle=%p,%d", __initedMainBundle, __initedMainBundle ? *__initedMainBundle : 0);
        *__initedMainBundle = 0; // force re-init main bundle
    }

    SYSLOG("NXArgv[0] = %s", NXArgv[0]);
    SYSLOG("_NSGetArgv()[0] = %s", (*_NSGetArgv())[0]);
    SYSLOG("_CFGetProcessPath = %s", *_CFGetProcessPath());
    SYSLOG("NSBundle.mainBundle.bundlePath = %d,%@", NSBundle.mainBundle.isLoaded, NSBundle.mainBundle.bundlePath);
    SYSLOG("NSBundle.mainBundle.executablePath = %d,%@", NSBundle.mainBundle.isLoaded, NSBundle.mainBundle.executablePath);
    SYSLOG("CFMainBundleURL = %@", (__bridge NSURL*)CFBundleCopyBundleURL(CFBundleGetMainBundle()));
    SYSLOG("CFMainBundleExecutableURL = %@", (__bridge NSURL*)CFBundleCopyExecutableURL(CFBundleGetMainBundle()));
    SYSLOG("NSProcessInfo.processInfo.arguments = %@", NSProcessInfo.processInfo.arguments);
    SYSLOG("dyld_image_path_containing_address = %p,%s", dyld_image_path_containing_address(_dyld_get_prog_image_header()), dyld_image_path_containing_address(_dyld_get_prog_image_header()));
    for(int i=0; i<_dyld_image_count(); i++) {
        if((void*)_dyld_get_image_header(i) == (void*)_dyld_get_prog_image_header()) {
            SYSLOG("_dyld_get_image_name(%d) = %p,%s", i, _dyld_get_image_name(i), _dyld_get_image_name(i));
        }
    }
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


bool (*NSConcreteTask_launchWithDictionary_error__orig)(id self, SEL _cmd, NSDictionary *dictionary, NSError **errorOut);
bool NSConcreteTask_launchWithDictionary_error__hook(id self, SEL _cmd, NSDictionary *dictionary, NSError **errorOut)
{
	if (dictionary)
    {
        SYSLOG("NSConcreteTask launchWithDictionary: %@", dictionary);
        
        NSDictionary* envDict = [dictionary objectForKey:@"_NSTaskEnvironmentDictionary"];
        NSMutableDictionary* newEnvDict = nil;
        if(envDict)
        {
            newEnvDict = [envDict mutableCopy];
        }
        else
        {
            newEnvDict = [NSMutableDictionary new];

            int i = 0;
            while(environ[i]) {
                char *key = NULL;
                char *value = NULL;
                char *full = strdup(environ[i++]);
                char *tok = strtok(full, "=");
                if (tok) {
                    key = strdup(tok);
                    tok = strtok(NULL, "=");
                    if (tok) {
                        value = strdup(tok);
                    }
                }
                if (full) free(full);

                if (key && value) {
                    newEnvDict[@(key)] = @(value);
                }
                if (key) free(key);
                if (value) free(value);
            }
        }

        NSString* dyldInsertLibs = newEnvDict[@"DYLD_INSERT_LIBRARIES"];
        const char* preload = dyldInsertLibs ? [dyldInsertLibs UTF8String] : NULL;
        if(!preload || !strstr(preload, "/basebin/bootstrap.dylib"))
        {
            const char* bootstrapath = jbroot("/basebin/bootstrap.dylib");
            if(preload && *preload) {
                char newpreload[strlen(preload)+strlen(bootstrapath)+2];
                snprintf(newpreload, sizeof(newpreload), "%s:%s", bootstrapath, preload);
                newEnvDict[@"DYLD_INSERT_LIBRARIES"] = @(newpreload);
            } else {
                newEnvDict[@"DYLD_INSERT_LIBRARIES"] = @(bootstrapath);
            }
        }
        if(g_sandbox_extensions) {
            newEnvDict[@"__SANDBOX_EXTENSIONS"] = @(g_sandbox_extensions);
        }

        NSMutableDictionary* newLaunchDict = [dictionary mutableCopy];
        newLaunchDict[@"_NSTaskEnvironmentDictionary"] = newEnvDict;
        dictionary = newLaunchDict.copy;
	}
    return NSConcreteTask_launchWithDictionary_error__orig(self, _cmd, dictionary, errorOut);
}

void hook_NSTask(void)
{
    SYSLOG("hook_NSTask %d", getpid());
    hook_instance_method(NSClassFromString(@"NSConcreteTask"), @selector(launchWithDictionary:error:), NSConcreteTask_launchWithDictionary_error__hook, (void**)&NSConcreteTask_launchWithDictionary_error__orig);
}
