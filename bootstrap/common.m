#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <sys/syslog.h>

#include "common.h"
#include "../bootstrapd/libbsd.h"

void bootstrapLog(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    NSString* log = [[NSString alloc] initWithFormat:@(format) arguments:ap];
    va_end(ap);

    // fprintf(stderr, "%s\n", log.UTF8String);
    // fflush(stderr);

    openlog("bootstrap",LOG_PID,LOG_AUTH);
    syslog(LOG_DEBUG, "%s", log.UTF8String);
    closelog();
}

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

void varCleanInit()
{
    SYSLOG("varClean: init...");

    if([NSHomeDirectory().stringByStandardizingPath hasPrefix:@"/var/mobile/Containers/"]) {
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        static NSOperationQueue* queue;

        queue = [NSOperationQueue new];
        queue.maxConcurrentOperationCount = 1;

        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil
             queue:queue usingBlock:^(NSNotification* note) {
            SYSLOG("varClean UIApplicationDidEnterBackgroundNotification %@", note);
            bsd_varClean();
        }];

        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationWillTerminateNotification object:nil
            queue:queue usingBlock:^(NSNotification* note) {
           SYSLOG("varClean UIApplicationWillTerminateNotification %@", note);
           bsd_varClean();
        }];

        SYSLOG("varClean init in main queue");
    });
}

bool isTrollStoredApp()
{
    return [NSFileManager.defaultManager fileExistsAtPath:[NSString stringWithFormat:@"%@/../_TrollStore", NSBundle.mainBundle.bundlePath]];
}
