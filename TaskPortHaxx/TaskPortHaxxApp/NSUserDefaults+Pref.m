//
//  NSUserDefaults+Pref.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 2/11/25.
//

@import Foundation;
#import "Header.h"

@implementation NSUserDefaults(Pref)
- (void)setSignedPointer:(NSUInteger)signedPointer {
    [self setObject:@(signed_pointer = signedPointer) forKey:@"signedPointer"];
}
- (NSUInteger)signedPointer {
    return signed_pointer = [[self objectForKey:@"signedPointer"] unsignedIntegerValue];
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
