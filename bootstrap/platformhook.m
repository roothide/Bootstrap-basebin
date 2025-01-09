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
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */
int csops(pid_t pid, uint32_t ops, void* useraddr, user_size_t usersize);
int csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int new_csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token)
{
    int ret = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    if(ret==-1) ret = csops(getpid(), ops, useraddr, usersize);

    NSLog(@"csops_audittoken(%d): %d : %d %08X %lx %p", ops, ret, pid, useraddr ? *(uint32_t*)useraddr : 0, usersize, token);

    if(ops==CS_OPS_STATUS) {
        *(uint32_t*)useraddr |= CS_VALID;
        *(uint32_t*)useraddr |= CS_PLATFORM_BINARY;
        *(uint32_t*)useraddr &= ~CS_PLATFORM_PATH;
    }

    return ret;
}

void init_platformHook()
{    
    NSLog(@"init_platformHook %d", getpid());

    if(requireJIT()!=0) return;
    
    DobbyHook(csops_audittoken, new_csops_audittoken, (void**)&orig_csops_audittoken);
    // DobbyHook(os_variant_has_internal_content, new_os_variant_has_internal_content, (void**)&orig_os_variant_has_internal_content);
}

@interface NSUserDefaults(SafariCoreExtras)
+ (NSUserDefaults*) safari_browserDefaults;
@end

@implementation NSUserDefaults(SafariCoreExtras)
+ (NSUserDefaults*) safari_browserDefaults
{
    static NSUserDefaults* _appDefaults = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString* path = [NSString stringWithFormat:@"%s/Library/Preferences/%@.plist", getenv("HOME"), NSBundle.mainBundle.bundleIdentifier];
        NSLog(@"safari_browserDefaults %@", path);
        _appDefaults = [[NSUserDefaults alloc] initWithSuiteName:path];
        NSLog(@"_appDefaults %@", _appDefaults);
    });
    return _appDefaults;
}
@end

@interface LSApplicationWorkspace : NSObject
+(instancetype)defaultWorkspace;
-(BOOL)openApplicationWithBundleID:(id)arg1 ;
-(id)pluginsWithIdentifiers:(id)arg1 protocols:(id)arg2 version:(id)arg3 ;
-(id)pluginsWithIdentifiers:(id)arg1 protocols:(id)arg2 version:(id)arg3 applyFilter:(/*^block*/id)arg4 ;
-(id)pluginsWithIdentifiers:(id)arg1 protocols:(id)arg2 version:(id)arg3 withFilter:(/*^block*/id)arg4 ;
-(void)enumeratePluginsMatchingQuery:(id)arg1 withBlock:(/*^block*/id)arg2 ;
-(id)pluginsMatchingQuery:(id)arg1 applyFilter:(/*^block*/id)arg2 ;
@end

#include <dlfcn.h>
void launchBootstrapApp()
{
    dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW);
    Class class_LSApplicationWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    [[class_LSApplicationWorkspace defaultWorkspace] openApplicationWithBundleID:@"com.roothide.Bootstrap"];
}