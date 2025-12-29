//
//  NSUserDefaults+Pref.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 2/11/25.
//

@import Foundation;
#import "Header.h"
#include <roothide.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation NSUserDefaults(Pref)
-(id)objectForKey:(NSString*)key {
    NSString *configFilePath = jbroot(@TASKPORTHAXX_CACHE_DIR"/Cache.plist");
    NSDictionary* defaults = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    return [defaults objectForKey:key];
}

-(void)setObject:(NSObject*)value forKey:(NSString*)key {
    NSFileManager *fm = NSFileManager.defaultManager;
    if(![fm fileExistsAtPath:jbroot(@TASKPORTHAXX_CACHE_DIR)]) {
        assert([fm createDirectoryAtPath:jbroot(@TASKPORTHAXX_CACHE_DIR) withIntermediateDirectories:YES attributes:nil error:nil]);
    }
    NSString *configFilePath = jbroot(@TASKPORTHAXX_CACHE_DIR"/Cache.plist");
    NSMutableDictionary* defaults = [NSMutableDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!defaults) defaults = [[NSMutableDictionary alloc] init];
    [defaults setValue:value forKey:key];
    assert([defaults writeToFile:configFilePath atomically:YES]);
}
- (void)setSignedPointer:(NSUInteger)signedPointer {
    [self setObject:@(signedPointer) forKey:@"signedPointer"];
}
- (NSUInteger)signedPointer {
    return [[self objectForKey:@"signedPointer"] unsignedIntegerValue];
}
- (void)setSignedDiversifier:(uint32_t)signedDiversifier {
    [self setObject:@(signedDiversifier) forKey:@"signedDiversifier"];
}
- (uint32_t)signedDiversifier {
    return [[self objectForKey:@"signedDiversifier"] unsignedIntValue];
}
- (void)setOffsetLaunchdPath:(NSUInteger)off {
    [self setObject:@(off) forKey:@"offsetLaunchdPath"];
}
- (NSUInteger)offsetLaunchdPath {
    return [[self objectForKey:@"offsetLaunchdPath"] unsignedIntegerValue];
}
- (void)setOffsetAMFI:(NSUInteger)off {
    [self setObject:@(off) forKey:@"offsetAMFI"];
}
- (NSUInteger)offsetAMFI {
    return [[self objectForKey:@"offsetAMFI"] unsignedIntegerValue];
}
@end

#pragma clang diagnostic pop
