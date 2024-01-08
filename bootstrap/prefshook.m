#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>

#include <roothide.h>
#include "common.h"
#include "fishhook.h"
#include "dobby.h"


NSArray* stockPrefsIdentifiers = @[
    @".GlobalPreferences",
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

// Boolean CFPreferencesAppSynchronize(CFStringRef applicationID)
// {

// }


// Boolean (*orig_CFPreferencesSynchronize)(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName)=NULL;
// Boolean new_CFPreferencesSynchronize(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName)
// {
//     Boolean retval = orig_CFPreferencesSynchronize(applicationID, userName, hostName);
//     NSLog(@"prefshook: CFPreferencesSynchronize: %@ %@ %@ : %d", applicationID, userName, hostName, retval);

//     // NSLog(@"prefshook: CFPreferencesAppSynchronize=%d", CFPreferencesAppSynchronize(applicationID));

//     NSString* plistPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", applicationID];

//     CFArrayRef keyList = CFPreferencesCopyKeyList(applicationID, userName, hostName);
//     if (keyList != nil) 
//     {
//         NSDictionary* prefs = (NSDictionary *)CFBridgingRelease(CFPreferencesCopyMultiple(keyList, applicationID, userName, hostName));
//         if (prefs == nil)
//             prefs = [NSDictionary dictionary];

//         NSLog(@"prefshook: dict %@", prefs);

//         ASSERT([prefs writeToFile:jbroot(plistPath) atomically:YES]);

//         CFRelease(keyList);
//     }

//     return retval;
// }

Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, void* unk);
Boolean (*orig_CFPreferencesSynchronizeWithContainer)(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, void* unk);
Boolean new_CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, void* unk)
{
    NSLog(@"prefshook: _CFPreferencesSynchronizeWithContainer: %@ %@ %@", applicationID, userName, hostName);

    NSString* identifier = (__bridge NSString*)applicationID;
    if([identifier hasPrefix:@"/var/mobile/Library/Preferences/"]) 
        identifier = identifier.lastPathComponent;

    // NSLog(@"prefshook: CFPreferencesAppSynchronize=%d", CFPreferencesAppSynchronize(applicationID));

    NSString* plistPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", identifier];

    CFArrayRef keyList = CFPreferencesCopyKeyList(applicationID, userName, hostName);
    if (keyList != nil) 
    {
        NSDictionary* prefs = (NSDictionary *)CFBridgingRelease(CFPreferencesCopyMultiple(keyList, applicationID, userName, hostName));
        if (prefs == nil)
            prefs = [NSDictionary dictionary];

        NSLog(@"prefshook: dict %@", prefs);

        ASSERT([prefs writeToFile:jbroot(plistPath) atomically:YES]);

        CFRelease(keyList);
    }


    Boolean retval = true;

    if(applicationID==kCFPreferencesAnyApplication
        ||[identifier hasPrefix:@"com.apple."]
	    || [identifier hasPrefix:@"group.com.apple."]
	    || [identifier hasPrefix:@"systemgroup.com.apple."]
        || [stockPrefsIdentifiers containsObject:identifier]
    ) 
    {
        retval = orig_CFPreferencesSynchronizeWithContainer(applicationID, userName, hostName, unk);
    }
    else if([NSFileManager.defaultManager fileExistsAtPath:plistPath]) 
    {
        // ASSERT([NSFileManager.defaultManager removeItemAtPath:plistPath error:nil]);
    }
    
    return retval;
}


void init_prefshook()
{
    NSLog(@"init_prefshook %d", getpid());

    if(requireJIT()!=0) return;

    // struct rebinding rebindings[] = {
    //     {"CFPreferencesSynchronize", new_CFPreferencesSynchronize, (void**)&orig_CFPreferencesSynchronize},
    // };
    // struct mach_header_64* header = _dyld_get_prog_image_header();
    // rebind_symbols_image((void*)header, _dyld_get_image_slide(header), rebindings, sizeof(rebindings)/sizeof(rebindings[0]));

    // dobby_enable_near_branch_trampoline();
    // DobbyHook(CFPreferencesSynchronize, new_CFPreferencesSynchronize, (void**)&orig_CFPreferencesSynchronize); //short function!

    DobbyHook(_CFPreferencesSynchronizeWithContainer, new_CFPreferencesSynchronizeWithContainer, (void**)&orig_CFPreferencesSynchronizeWithContainer);
}

