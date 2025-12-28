#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <sys/syslog.h>

#include "common.h"
#include "libbsd.h"

#if DEBUG
void (*bootstrapLogFunction)(const char* format, ...) = NULL;
void bootstrapLog(const char* format, ...)
{
    openlog("bootstrap",LOG_PID,LOG_AUTH);
    va_list ap;
    va_start(ap, format);
    vsyslog(LOG_DEBUG, format, ap);
    va_end(ap);
    closelog();
}
#endif

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
            SYSLOG("varClean UIApplicationDidEnterBackgroundNotification %s", note.debugDescription.UTF8String);
            bsd_varClean();
        }];

        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationWillTerminateNotification object:nil
            queue:queue usingBlock:^(NSNotification* note) {
           SYSLOG("varClean UIApplicationWillTerminateNotification %s", note.debugDescription.UTF8String);
           bsd_varClean();
        }];

        SYSLOG("varClean init in main queue");
    });
}
