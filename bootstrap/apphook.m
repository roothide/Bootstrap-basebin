#include <Foundation/Foundation.h>
#include <objc/message.h>
#include <roothide.h>

#include "../bootstrapd/libbsd.h"

#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-variable"



#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

BOOL isDefaultInstallationPath(NSString* _path)
{
    if(!_path) return NO;

    const char* path = _path.UTF8String;
    
    char rp[PATH_MAX];
    if(!realpath(path, rp)) return NO;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NO;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NO;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NO;

    return YES;
}


@interface LSApplicationWorkspace : NSObject @end

NSArray* blockedURLSchemes = @[
    @"filza", 
    @"db-lmvo0l08204d0a0",
    @"boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
    @"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
    @"sileo",
    @"zbra", 
    @"santander", 
    @"icleaner", 
    @"xina", 
    @"ssh",
    @"apt-repo", 
    @"cydia",
    @"activator",
    @"postbox",
];

NSArray* blockedAppPlugins = @[
    @"com.tigisoftware.Filza.Sharing",
];

BOOL LSApplicationWorkspace_registerApplicationDictionary_(Class self, SEL sel, NSMutableDictionary* applicationDictionary)
{
    // NSLog(@"registerApplicationDictionary: %@", applicationDictionary[@"Path"]);

    NSString* bundlePath = applicationDictionary[@"Path"];
    NSString* appInfoPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSMutableDictionary *appInfoPlist = [NSMutableDictionary dictionaryWithContentsOfFile:appInfoPath];

    //NSLog(@"Info=%@", appInfoPlist);
    NSMutableArray* urltypes = [appInfoPlist[@"CFBundleURLTypes"] mutableCopy];
    for(int i=0; i<urltypes.count; i++) {
       //NSLog(@"schemes=%@", urltypes[i][@"CFBundleURLSchemes"]);
        
        NSMutableArray* schemes = [urltypes[i][@"CFBundleURLSchemes"] mutableCopy];
        [schemes removeObjectsInArray:blockedURLSchemes];
        //NSLog(@"new schemes=%@", schemes);

        urltypes[i][@"CFBundleURLSchemes"] = schemes.copy;
    }
    appInfoPlist[@"CFBundleURLTypes"] = urltypes.copy;

    //NSLog(@"plugins=%@", applicationDictionary[@"_LSBundlePlugins"]);
    for(NSString* pluginId in applicationDictionary[@"_LSBundlePlugins"])
    {
        if([blockedAppPlugins containsObject:pluginId]) {
            //NSLog(@"blocked pluginId=%@", pluginId);
            [applicationDictionary[@"_LSBundlePlugins"] removeObjectForKey:pluginId];
        }
    }

    BOOL isAppleApp = [appInfoPlist[@"CFBundleIdentifier"] hasPrefix:@"com.apple."];

    NSString* jbrootpath = [bundlePath stringByAppendingPathComponent:@".jbroot"];
    BOOL jbrootexists = [NSFileManager.defaultManager fileExistsAtPath:jbrootpath];

    NSString* executableName = appInfoPlist[@"CFBundleExecutable"];

    unlink([bundlePath stringByAppendingPathComponent:@".preload"].UTF8String);
    unlink([bundlePath stringByAppendingPathComponent:@".prelib"].UTF8String);
    
    NSString* rebuildFile = [bundlePath stringByAppendingPathComponent:@".rebuild"];

    if(jbrootexists) 
    {
        if(![NSFileManager.defaultManager fileExistsAtPath:rebuildFile])
        {
            NSLog(@"patch macho: %@", [bundlePath stringByAppendingPathComponent:executableName]);
            int patch_app_exe(const char* file);
            patch_app_exe([bundlePath stringByAppendingPathComponent:executableName].UTF8String);

            int execBinary(const char* path, const char** argv);
            const char* argv[] = {"/basebin/rebuildapp", rootfs(bundlePath).UTF8String, NULL};
            assert(execBinary(jbroot(argv[0]), argv) == 0);
            
            [[NSString new] writeToFile:rebuildFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
       }

        link(jbroot("/basebin/preload"), [bundlePath stringByAppendingPathComponent:@".preload"].UTF8String);
        link(jbroot("/basebin/preload.dylib"), [bundlePath stringByAppendingPathComponent:@".prelib"].UTF8String);

        NSMutableDictionary* newEnvironmentVariables = [applicationDictionary[@"EnvironmentVariables"] mutableCopy];
        newEnvironmentVariables[@"_JBROOT"] = jbroot(@"/");
        newEnvironmentVariables[@"_SBTOKEN"] = [NSString stringWithUTF8String:bsd_getsbtoken()];
        applicationDictionary[@"EnvironmentVariables"] = newEnvironmentVariables;

        
        [appInfoPlist writeToFile:appInfoPath atomically:YES];
    }
    else
    {
        unlink(rebuildFile.UTF8String);
    }

    if(isDefaultInstallationPath(bundlePath)) {
        applicationDictionary[@"IsDeletable"] = @YES;
    }

    BOOL retval = ( (BOOL* (*)(Class self, SEL sel, NSDictionary* applicationDictionary)) objc_msgSend) (self,sel, applicationDictionary);

    return retval;
}

bool isKindOf(Class clazz, Class super)
{
    for (Class tcls = clazz; tcls; tcls = class_getSuperclass(tcls)) {
        if(tcls == super) return true;
    }
    return false;
}

void* objc_msgSend_hook(void* self, SEL sel, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, ... )
{
    bool isClass = object_isClass((__bridge id)self);
    Class clazz =  isClass ? (__bridge Class)self : object_getClass((__bridge id)self);

    //LOG(@"objc_msgSend %@ %@", NSStringFromClass(clazz), NSStringFromSelector(sel));

    if(isKindOf(clazz, LSApplicationWorkspace.self)
     && sel_isEqual(sel, @selector(registerApplicationDictionary:)) )
    {
        return (void*)LSApplicationWorkspace_registerApplicationDictionary_;
    }

    return (void*)objc_msgSend;
}

void (*apphook_orig_objc_msgSend)();
__attribute__((naked)) void apphook_new_objc_msgSend()
{
    asm("\
    stp fp, lr, [sp, #-16]! \n\
    stp x8, x9, [sp, #-16]! \n\
    stp x6, x7, [sp, #-16]! \n\
    stp x4, x5, [sp, #-16]! \n\
    stp x2, x3, [sp, #-16]! \n\
    stp x0, x1, [sp, #-16]! \n\
    stp q6, q7, [sp, #-32]! \n\
    stp q4, q5, [sp, #-32]! \n\
    stp q2, q3, [sp, #-32]! \n\
    stp q0, q1, [sp, #-32]! \n\
\
    bl _objc_msgSend_hook \n\
    mov x17, x0 \n\
\
    ldp q0, q1, [sp], #32 \n\
    ldp q2, q3, [sp], #32 \n\
    ldp q4, q5, [sp], #32 \n\
    ldp q6, q7, [sp], #32 \n\
    ldp x0, x1, [sp], #16 \n\
    ldp x2, x3, [sp], #16 \n\
    ldp x4, x5, [sp], #16 \n\
    ldp x6, x7, [sp], #16 \n\
    ldp x8, x9, [sp], #16 \n\
    ldp fp, lr, [sp], #16 \n\
    ");

#ifdef __arm64e__
    asm("braaz x17");
#else
    asm("br x17");
#endif

}