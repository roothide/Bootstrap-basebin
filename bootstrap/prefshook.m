#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pwd.h>
#include <roothide.h>
#include "fishhook.h"
#include "sandbox.h"
#include "common.h"
#include "dobby.h"

NSArray* stockPrefsIdentifiers = @[
    @".GlobalPreferences", //kCFPreferencesAnyApplication
    @".GlobalPreferences_m",
    @"bluetoothaudiod",
    @"NetworkInterfaces",
    @"OSThermalStatus",
    @"preferences",
    @"osanalyticshelper",
    @"UserEventAgent",
    @"wifid",
    @"dprivacyd",
    @"silhouette",
    @"nfcd",
    @"kNPProgressTrackerDomain",
    @"siriknowledged",
    @"UITextInputContextIdentifiers",
    @"mobile_storage_proxy",
    @"splashboardd",
    @"mobile_installation_proxy",
    @"languageassetd",
    @"ptpcamerad",
    @"com.google.gmp.measurement.monitor",
    @"com.google.gmp.measurement",
];


bool isAppleInternalIdentifier(const char*);

BOOL prefsRedirection(NSString** pidentifier, NSString** pcontainer)
{
    SYSLOG("prefsRedirection:%@ container=%@ bundleIdentifier=%@ homedir=%@", *pidentifier, *pcontainer, NSBundle.mainBundle.bundleIdentifier, NSHomeDirectory());

    NSString* container = *pcontainer;
    NSString* identifier = *pidentifier;

    if([identifier isEqualToString:(__bridge NSString*)kCFPreferencesAnyApplication]) {
        return NO;
    }

    NSString* bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if(!bundleIdentifier) {
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        ASSERT(_NSGetExecutablePath(executablePath, &bufsize) == 0);
        
        bundleIdentifier = [@(executablePath) lastPathComponent];
    }
    if([bundleIdentifier hasSuffix:@".plist"]) {
        bundleIdentifier = bundleIdentifier.stringByDeletingPathExtension;
    }

    NSFileManager* fm = NSFileManager.defaultManager;

    //check if is a absolute path first
    if([identifier hasPrefix:@"/"]) {
        
        NSString *pattern = @"^((?:/private)?/var/\\w+)/Library/Preferences/(.+)";
        NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
        NSTextCheckingResult* match = [regex firstMatchInString:identifier options:0 range:NSMakeRange(0, identifier.length)];
        if(!match) {
            return NO;
        }
        
        NSString* __container = [identifier substringWithRange:[match rangeAtIndex:1]];
        NSString* __identifier = [identifier substringWithRange:[match rangeAtIndex:2]];
        if([__identifier hasSuffix:@".plist"]) {
            __identifier = __identifier.stringByDeletingPathExtension;
        }

        //check after stripping .plist suffix
        if([__identifier isEqualToString:(__bridge NSString*)kCFPreferencesCurrentApplication]) {
            __identifier = bundleIdentifier;
        }
        
        if(!isAppleInternalIdentifier(__identifier.UTF8String)
            && ([stockPrefsIdentifiers containsObject:__identifier]
                            || [__identifier hasPrefix:@"com.apple."]
                            || [__identifier hasPrefix:@"group.com.apple."]
                            || [__identifier hasPrefix:@"systemgroup.com.apple."]) )
        {
            return NO;
        }
        
        identifier = __identifier;
        container = jbroot(__container);
    }
    else if(container) {
        NSString *pattern = @"^(?:/private)?/var/\\w+(?:/)?$";
        NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
        NSTextCheckingResult* match = [regex firstMatchInString:container options:0 range:NSMakeRange(0, container.length)];
        if(!match) {
            return NO;
        }
        
        //check before stripping .plist suffix
        if([identifier isEqualToString:(__bridge NSString*)kCFPreferencesCurrentApplication]) {
            identifier = bundleIdentifier;
        }

        if([identifier hasSuffix:@".plist"]) {
            identifier = identifier.stringByDeletingPathExtension;
        }
        
        if(!isAppleInternalIdentifier(identifier.UTF8String)
            && ([stockPrefsIdentifiers containsObject:identifier]
                        || [identifier hasPrefix:@"com.apple."]
                        || [identifier hasPrefix:@"group.com.apple."]
                        || [identifier hasPrefix:@"systemgroup.com.apple."]) )
        {
            return NO;
        }

        container = jbroot(container);
    }
    else if(identifier) {
        
        //check before stripping .plist suffix
        if([identifier isEqualToString:(__bridge NSString*)kCFPreferencesCurrentApplication]) {
            identifier = bundleIdentifier;
        }
    
        if([identifier hasSuffix:@".plist"]) {
            identifier = identifier.stringByDeletingPathExtension;
        }
        
        if([identifier hasPrefix:@"group."]
            && [fm containerURLForSecurityApplicationGroupIdentifier:identifier]) {
            return NO;
        }

        NSString* homeContainer = NSHomeDirectory();

        if(![identifier isEqualToString:bundleIdentifier])
        {
            if(!isAppleInternalIdentifier(identifier.UTF8String)
                && ([stockPrefsIdentifiers containsObject:identifier]
                                || [identifier hasPrefix:@"com.apple."]
                                || [identifier hasPrefix:@"group.com.apple."]
                                || [identifier hasPrefix:@"systemgroup.com.apple."]) )
            {
                /* a sandbox process can also be able to read some built-in com.apple.* preferences
                so we need to skip them if a removable system app is unsandboxed(enabled tweaks).
                */
                if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0)
                {
                    //Not very reliable but we don't seem to have any other better way to determine it
                    if([homeContainer hasPrefix:@"/var/mobile/Containers/"] || [homeContainer hasPrefix:@"/private/var/mobile/Containers/"]) {
                        if(![fm fileExistsAtPath:[NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", homeContainer, identifier]]) {
                            return NO;
                        }
                    } else {
                        return NO;
                    }
                }
                else
                {
                    uint64_t flags = SANDBOX_CHECK_NO_REPORT|SANDBOX_CHECK_ALLOW_APPROVAL|SANDBOX_FILTER_GLOBAL_NAME|SANDBOX_FILTER_APPLEEVENT_DESTINATION;
                    if(sandbox_check(getpid(), "user-preference-read", flags, identifier.UTF8String) == 0) {
                        return NO;
                    }
                }
            }
            else
            {
                NSString *pattern = @"^(?:/private)?/var/\\w+(?:/)?$";
                NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
                NSTextCheckingResult* match = [regex firstMatchInString:homeContainer options:0 range:NSMakeRange(0, homeContainer.length)];
                if(match) {
                    homeContainer = jbroot(homeContainer);
                }
            }
        }

        container = homeContainer;
    }
    else
    {
        identifier = bundleIdentifier;
        container = NSHomeDirectory();
    }

    //migrating plist from previous versions
    struct passwd *pw = getpwuid(geteuid());
    if(pw && pw->pw_name) {
        NSString* plistPath = [NSString stringWithFormat:@"/var/%s/Library/Preferences/%@.plist", pw->pw_name, identifier];
        NSString* plistNewPath = [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", container, identifier];
        if([fm fileExistsAtPath:plistPath] && ![fm fileExistsAtPath:plistNewPath])
        {
            BOOL copy=[fm copyItemAtPath:plistPath toPath:plistNewPath error:nil];
            BOOL remove=[fm removeItemAtPath:plistPath error:nil];
            NSLog(@"prefshook: copy=%d remove=%d %@ -> %@", copy, remove, plistPath, plistNewPath);
        }
    }

    NSLog(@"prefshook: prefs redirect to %@ : %@", identifier, container);
    *pcontainer = container;
    *pidentifier = identifier;
    return YES;
}


bool __thread gInSync = false;

CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(_Nullable CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);

void SynchronizePlist(NSString* identifier, NSString* container)
{
    NSLog(@"SynchronizePlist: %@ : %@", identifier, container);

    if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0)
    {

        NSString* plistPath = [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", container, identifier];

        CFArrayRef keyList = _CFPreferencesCopyKeyListWithContainer((__bridge CFStringRef)identifier, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost, (__bridge CFStringRef)container);
        if(keyList) {
            CFDictionaryRef prefs = _CFPreferencesCopyMultipleWithContainer(keyList, (__bridge CFStringRef)identifier, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost, (__bridge CFStringRef)container);
            if(prefs) {
                
                NSDictionary* dict = (__bridge NSDictionary *)prefs;
                [dict writeToFile:plistPath atomically:YES];
                
                CFRelease(prefs);
            }
            CFRelease(keyList);
        }
    }
}


#include <objc/runtime.h>
void hook_class_method(Class clazz, SEL selector, void* replacement, void** old_ptr){
    Method method = class_getClassMethod(clazz, selector);
    if (method == NULL) {
        SYSLOG("hook_class_method: method not found: %@ : %@", NSStringFromClass(clazz), NSStringFromSelector(selector));
        return;
    }
    *old_ptr = (void*)method_getImplementation(method);
    method_setImplementation(method, (IMP)replacement);
}

void hook_instance_method(Class clazz, SEL selector, void* replacement, void** old_ptr){
    Method method = class_getInstanceMethod(clazz, selector);
    if (method == NULL) {
        SYSLOG("hook_instance_method: method not found: %@ : %@", NSStringFromClass(clazz), NSStringFromSelector(selector));
        return;
    }
    *old_ptr = (void*)method_getImplementation(method);
    method_setImplementation(method, (IMP)replacement);
}

NSUserDefaults* (*orig_NSUserDefaults__initWithSuiteName_container_)(id self, SEL _cmd, NSString* suiteName, NSURL* container);
NSUserDefaults* new_NSUserDefaults__initWithSuiteName_container_(id self, SEL _cmd, NSString* suiteName, NSURL* container)
{
    SYSLOG("prefshook: NSUserDefaults(%p) _initWithSuiteName:%@ container:%@", self, suiteName, container);

    //-[NSUserDefaults initWithSuiteName:] does not allow identifier=NSBundle.mainBundle.bundleIdentifier
    if([suiteName isEqualToString:NSGlobalDomain] || [suiteName isEqualToString:NSBundle.mainBundle.bundleIdentifier])
    {
        //make sure Apple hasn't changed its behavior
        NSUserDefaults* ret = orig_NSUserDefaults__initWithSuiteName_container_(self, _cmd, suiteName, container);
        ASSERT(ret == nil);
        return nil;
    }

    NSString* containerPath = container.path;
    BOOL redirected = prefsRedirection(&suiteName, &containerPath);
    if(redirected)
    {
        container = [NSURL fileURLWithPath:containerPath];
        if([suiteName isEqualToString:NSBundle.mainBundle.bundleIdentifier]) {
            suiteName = nil;
        }
    }

    NSUserDefaults* result = orig_NSUserDefaults__initWithSuiteName_container_(self, _cmd, suiteName, container);

    return result;
}

void _CFXPreferencesRegisterDefaultValues(CFDictionaryRef defaults);

void init_prefs_objchook()
{
    SYSLOG("init_prefs_objchook %d", getpid());

    // standardUserDefaults -> init -> initWithUser:nil -> initWithSuiteName:nil
    // hook_class_method(NSUserDefaults.class, @selector(standardUserDefaults), new_NSUserDefaults_standardUserDefaults, (void**)&orig_NSUserDefaults_standardUserDefaults);
    // hook_instance_method(NSUserDefaults.class, @selector(initWithSuiteName:), new_NSUserDefaults_initWithSuiteName_, (void**)&orig_NSUserDefaults_initWithSuiteName_);
    hook_instance_method(NSUserDefaults.class, @selector(_initWithSuiteName:container:), new_NSUserDefaults__initWithSuiteName_container_, (void**)&orig_NSUserDefaults__initWithSuiteName_container_);

    //register default values first (both for NSUserDefaults and CFPreferences)
    CFArrayRef keyList = CFPreferencesCopyKeyList(kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
    if(keyList) {
        CFDictionaryRef prefs = CFPreferencesCopyMultiple(keyList, kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
        if(prefs) {
            _CFXPreferencesRegisterDefaultValues(prefs);
            CFRelease(prefs);
        }
        CFRelease(keyList);
    }
}


void* (*orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__)(id self, NSString* identifier, NSString* container, NSURL* cloudConfigurationURL, void* perform);
void* (*LEGACY_orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__)(id self, SEL _cmd, NSString* identifier, NSString* container, NSURL* cloudConfigurationURL, void* perform);
void* DISPATCH_orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(id self, NSString* identifier, NSString* container, NSURL* cloudConfigurationURL, void* perform)
{
    if(@available(iOS 17.0, *)) {
        return orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(self, identifier, container, cloudConfigurationURL, perform);
    } else {
        return LEGACY_orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(self, NULL, identifier, container, cloudConfigurationURL, perform);
    }
}
void* new___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(id self, NSString* identifier, NSString* container, NSURL* cloudConfigurationURL, void* perform)
{
    SYSLOG("prefshook: ___CFXPreferences_withSearchListForIdentifier=%@ container=%@ cloudConfigurationURL=%@", identifier, container, cloudConfigurationURL);

    BOOL redirected = prefsRedirection(&identifier, &container);

    void* result = DISPATCH_orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(self, identifier, container, cloudConfigurationURL, perform);

    return result;
}
void* LEGACY_new___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(id self, SEL _cmd, NSString* identifier, NSString* container, NSURL* cloudConfigurationURL, void* perform)
{
    return new___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__(self, identifier, container, cloudConfigurationURL, perform);
}



void* (*orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__)(id self, NSString* identifier, NSString* user, BOOL byHost, NSString* container, BOOL cloud, void* perform);
void* (*LEGACY_orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__)(id self, SEL _cmd, NSString* identifier, NSString* user, BOOL byHost, NSString* container, BOOL cloud, void* perform);
void* DISPATCH_orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(id self, NSString* identifier, NSString* user, BOOL byHost, NSString* container, BOOL cloud, void* perform)
{
    if(@available(iOS 17.0, *)) {
        return orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(self, identifier, user, byHost, container, cloud, perform);
    } else {
        return LEGACY_orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(self, NULL, identifier, user, byHost, container, cloud, perform);
    }
}
void* new___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(id self, NSString* identifier, NSString* user, BOOL byHost, NSString* container, BOOL cloud, void* perform)
{
    SYSLOG("prefshook: ___CFXPreferences_withSourceForIdentifier=%@ user=%@ byHost=%d container=%@ cloud=%d", identifier, user, byHost, container, cloud);

    BOOL redirected = prefsRedirection(&identifier, &container);

    void* result = DISPATCH_orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(self, identifier, user, byHost, container, cloud, perform);

    return result;
}
void* LEGACY_new___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(id self, SEL _cmd, NSString* identifier, NSString* user, BOOL byHost, NSString* container, BOOL cloud, void* perform)
{
    return new___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__(self, identifier, user, byHost, container, cloud, perform);
}



Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);
Boolean (*orig_CFPreferencesSynchronizeWithContainer)(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);
Boolean new_CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container)
{
    NSLog(@"prefshook: _CFPreferencesSynchronizeWithContainer: %@ userName=%@ hostName=%@ container=%@", applicationID, userName, hostName, container);

    Boolean ret = orig_CFPreferencesSynchronizeWithContainer(applicationID, userName, hostName, container);

    if(ret) {
        //(at least on 17.0) for some reason prefs is not written to plist immediately, so we need to sync it manually
        NSString* __identifier = (__bridge NSString*)applicationID;
        NSString* __container = (__bridge NSString*)container;
        if(prefsRedirection(&__identifier, &__container)) {
            SynchronizePlist(__identifier, __container);
        }
    }

    return ret;
}

void init_prefs_inlinehook()
{
    SYSLOG("init_prefs_inlinehook %d", getpid());

    if(requireJIT()!=0) return;

    DobbyHook(_CFPreferencesSynchronizeWithContainer, new_CFPreferencesSynchronizeWithContainer, (void**)&orig_CFPreferencesSynchronizeWithContainer);

    void* ___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__
                                                 = DobbySymbolResolver("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                                                         "-[_CFXPreferences withSearchListForIdentifier:container:cloudConfigurationURL:perform:]");
    SYSLOG("___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__=%p", ___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__);
    if(@available(iOS 17.0, *)) {
        DobbyHook(___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__, new___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__, (void**)&orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__);
    } else {
        DobbyHook(___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__, LEGACY_new___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__, (void**)&LEGACY_orig___CFXPreferences_withSearchListForIdentifier_container_cloudConfigurationURL_perform__);
    }

    void* ___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__
                                                 = DobbySymbolResolver("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                                                         "-[_CFXPreferences withSourceForIdentifier:user:byHost:container:cloud:perform:]");
    SYSLOG("___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__=%p", ___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__);
    if(@available(iOS 17.0, *)) {
        DobbyHook(___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__, new___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__, (void**)&orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__);
    } else {
        DobbyHook(___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__, LEGACY_new___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__, (void**)&LEGACY_orig___CFXPreferences_withSourceForIdentifier_user_byHost_container_cloud_perform__);
    }
}
