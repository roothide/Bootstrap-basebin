#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pwd.h>
#include <roothide.h>
#include "fishhook.h"
#include "sandbox.h"
#include "common.h"
#include "dobby.h"

NSArray* stockPrefsIdentifiers = @[
    @"Apple Global Domain", //kCFPreferencesAnyApplication
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

BOOL prefsRedirection(NSString** pidentifier, NSString** pcontainer)
{
    SYSLOG("prefsRedirection:%@ container=%@ bundleIdentifier=%@ homedir=%@ sandboxed=%d/containerized=%d", *pidentifier, *pcontainer, NSBundle.mainBundle.bundleIdentifier, NSHomeDirectory(), proc_is_sandboxed(), proc_is_containerized());
    
    uint64_t sandbox_preference_check_flags = SANDBOX_CHECK_NO_REPORT|SANDBOX_CHECK_ALLOW_APPROVAL|SANDBOX_FILTER_GLOBAL_NAME|SANDBOX_FILTER_APPLEEVENT_DESTINATION;

    SYSLOG("user-preference sandbox pre check %@ read=%d write=%d", *pidentifier,
        sandbox_check(getpid(), "user-preference-read", sandbox_preference_check_flags, (*pidentifier).UTF8String) == 0,
        sandbox_check(getpid(), "user-preference-write", sandbox_preference_check_flags, (*pidentifier).UTF8String) == 0
    );

    //_CFPrefsGetCacheStringForBundleID
    NSString* bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if(!bundleIdentifier) {
        bundleIdentifier = [@(g_executable_path) lastPathComponent];
    }
    if([bundleIdentifier hasSuffix:@".plist"]) {
        bundleIdentifier = bundleIdentifier.stringByDeletingPathExtension;
    }

    NSString* container = *pcontainer;
    NSString* identifier = *pidentifier;

    if(!identifier) {
        identifier = bundleIdentifier;
    }

    //Using kCFPreferencesAnyUser with a container is only allowed for System Containers
    if([identifier isEqualToString:(__bridge NSString*)kCFPreferencesAnyApplication]) {
        return NO;
    }

    if(container && [container isEqualToString:@"kCFPreferencesNoContainer"]) {
        container = nil;
    }

    NSFileManager* fm = NSFileManager.defaultManager;

    //check if is a absolute path first
    if([identifier hasPrefix:@"/"])
    {    
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
        
        if(!is_apple_internal_identifier(__identifier.UTF8String)
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
    else if(container)
    {
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
        
        if(!is_apple_internal_identifier(identifier.UTF8String)
            && ([stockPrefsIdentifiers containsObject:identifier]
                        || [identifier hasPrefix:@"com.apple."]
                        || [identifier hasPrefix:@"group.com.apple."]
                        || [identifier hasPrefix:@"systemgroup.com.apple."]) )
        {
            return NO;
        }

        container = jbroot(container);
    }
    else if(identifier)
    {
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
            if(!is_apple_internal_identifier(identifier.UTF8String)
                && ([stockPrefsIdentifiers containsObject:identifier]
                                || [identifier hasPrefix:@"com.apple."]
                                || [identifier hasPrefix:@"group.com.apple."]
                                || [identifier hasPrefix:@"systemgroup.com.apple."]) )
            {
                /* a sandbox process can also be able to read some built-in com.apple.* preferences
                    so we need to skip them if a removable system app is unsandboxed(enabled tweaks). */
                if(!proc_is_containerized())
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

    SYSLOG("user-preference sandbox post check %@ read=%d write=%d", identifier,
        sandbox_check(getpid(), "user-preference-read", sandbox_preference_check_flags, identifier.UTF8String) == 0,
        sandbox_check(getpid(), "user-preference-write", sandbox_preference_check_flags, identifier.UTF8String) == 0
    );

    //cfprefsd may reject a non-sandbox apple app to read/write preferences with container=/var/mobile
    //sandboxed but not containerized???
    if([container isEqualToString:@"/var/mobile"]) {
        return NO;
    }

    if(proc_is_sandboxed())
    {
        /*
        sandbox_init*
        <seatbelt-profiles>
        <com.apple.private.sandbox.profile>
        <com.apple.private.sandbox.profile:embedded>
        <com.apple.private.security.container-required>
        <com.apple.security.exception.shared-preference.read-only>
        <com.apple.security.exception.shared-preference.read-write>
        <com.apple.security.temporary-exception.shared-preference.read-only>
        <com.apple.security.temporary-exception.shared-preference.read-write>
        and more?
        */
        if(sandbox_check(getpid(), "user-preference-read", sandbox_preference_check_flags, identifier.UTF8String) == 0) {
            return NO;
        }
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
            SYSLOG("prefshook: copy=%d remove=%d %@ -> %@", copy, remove, plistPath, plistNewPath);
        }
    }

    SYSLOG("prefsRedirection: redirect to %@ : %@", identifier, container);
    *pcontainer = container;
    *pidentifier = identifier;
    return YES;
}

CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(_Nullable CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef container);

void SynchronizePlist(NSString* identifier, NSString* container)
{
    SYSLOG("SynchronizePlist: %@ : %@", identifier, container);

    NSString* plistDir = [NSString stringWithFormat:@"%@/Library/Preferences/", container];

    if (sandbox_check(getpid(), "file-write-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, plistDir.fileSystemRepresentation) == 0)
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
    SYSLOG("prefshook: _CFPreferencesSynchronizeWithContainer: %@ userName=%@ hostName=%@ container=%@", applicationID, userName, hostName, container);

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
