#include <stdio.h>
#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Security/SecKey.h>
#include <Security/Security.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <roothide.h>
#include "commlib.h"

int realstore(const char* path, const char* extra_entitlements, const char* strip_entitlements, const char* teamID);

// CSCommon.h
typedef struct CF_BRIDGED_TYPE(id) __SecCode const* SecStaticCodeRef; /* code on disk */

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0, /* no particular flags (default behavior) */

    kSecCSConsiderExpiration = 1U << 31,     /* consider expired certificates invalid */
    kSecCSEnforceRevocationChecks = 1 << 30, /* force revocation checks regardless of preference settings */
    kSecCSNoNetworkAccess = 1 << 29,         /* do not use the network, cancels "kSecCSEnforceRevocationChecks"  */
    kSecCSReportProgress = 1 << 28,          /* make progress report call-backs when configured */
    kSecCSCheckTrustedAnchors = 1 << 27,     /* build certificate chain to system trust anchors, not to any self-signed certificate */
    kSecCSQuickCheck = 1 << 26,              /* (internal) */
    kSecCSApplyEmbeddedPolicy = 1 << 25,     /* Apply Embedded (iPhone) policy regardless of the platform we're running on */
};

// SecStaticCode.h
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes,
                                                  SecStaticCodeRef* __nonnull CF_RETURNS_RETAINED staticCode);

// SecCode.h
CF_ENUM(uint32_t){
    kSecCSInternalInformation = 1 << 0, kSecCSSigningInformation = 1 << 1, kSecCSRequirementInformation = 1 << 2,
    kSecCSDynamicInformation = 1 << 3,  kSecCSContentInformation = 1 << 4, kSecCSSkipResourceDirectory = 1 << 5,
    kSecCSCalculateCMSDigest = 1 << 6,
};

OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef* __nonnull CF_RETURNS_RETAINED information);

extern const CFStringRef kSecCodeInfoEntitlements;    /* generic */
extern const CFStringRef kSecCodeInfoIdentifier;      /* generic */
extern const CFStringRef kSecCodeInfoRequirementData; /* Requirement */


typedef CF_OPTIONS(uint32_t, SecPreserveFlags) {
	kSecCSPreserveIdentifier = 1 << 0,
	kSecCSPreserveRequirements = 1 << 1,
	kSecCSPreserveEntitlements = 1 << 2,
	kSecCSPreserveResourceRules = 1 << 3,
	kSecCSPreserveFlags = 1 << 4,
	kSecCSPreserveTeamIdentifier = 1 << 5,
	kSecCSPreserveDigestAlgorithm = 1 << 6,
	kSecCSPreservePreEncryptHashes = 1 << 7,
	kSecCSPreserveRuntime = 1 << 8,
};

// SecCodeSigner.h
#ifdef BRIDGED_SECCODESIGNER
typedef struct CF_BRIDGED_TYPE(id) __SecCodeSigner* SecCodeSignerRef SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#else
typedef struct __SecCodeSigner* SecCodeSignerRef SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#endif

const CFStringRef kSecCodeSignerApplicationData = CFSTR("application-specific");
const CFStringRef kSecCodeSignerDetached =		CFSTR("detached");
const CFStringRef kSecCodeSignerDigestAlgorithm = CFSTR("digest-algorithm");
const CFStringRef kSecCodeSignerDryRun =		CFSTR("dryrun");
const CFStringRef kSecCodeSignerEntitlements =	CFSTR("entitlements");
const CFStringRef kSecCodeSignerFlags =			CFSTR("flags");
const CFStringRef kSecCodeSignerIdentifier =	CFSTR("identifier");
const CFStringRef kSecCodeSignerIdentifierPrefix = CFSTR("identifier-prefix");
const CFStringRef kSecCodeSignerIdentity =		CFSTR("signer");
const CFStringRef kSecCodeSignerPageSize =		CFSTR("pagesize");
const CFStringRef kSecCodeSignerRequirements =	CFSTR("requirements");
const CFStringRef kSecCodeSignerResourceRules =	CFSTR("resource-rules");
const CFStringRef kSecCodeSignerSDKRoot =		CFSTR("sdkroot");
const CFStringRef kSecCodeSignerSigningTime =	CFSTR("signing-time");
const CFStringRef kSecCodeSignerRequireTimestamp = CFSTR("timestamp-required");
const CFStringRef kSecCodeSignerTimestampServer = CFSTR("timestamp-url");
const CFStringRef kSecCodeSignerTimestampAuthentication = CFSTR("timestamp-authentication");
const CFStringRef kSecCodeSignerTimestampOmitCertificates =	CFSTR("timestamp-omit-certificates");
const CFStringRef kSecCodeSignerPreserveMetadata = CFSTR("preserve-metadata");
const CFStringRef kSecCodeSignerTeamIdentifier =	CFSTR("teamidentifier");
const CFStringRef kSecCodeSignerPlatformIdentifier = CFSTR("platform-identifier");


extern CFStringRef kSecCodeInfoEntitlementsDict;
extern CFStringRef kSecCodeInfoCertificates;
extern CFStringRef kSecPolicyAppleiPhoneApplicationSigning;
extern CFStringRef kSecPolicyAppleiPhoneProfileApplicationSigning;
extern CFStringRef kSecPolicyLeafMarkerOid;

SecStaticCodeRef getStaticCodeRef(NSString *binaryPath)
{
    if(binaryPath == nil)
    {
        return NULL;
    }
    
    CFURLRef binaryURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (__bridge CFStringRef)binaryPath, kCFURLPOSIXPathStyle, false);
    if(binaryURL == NULL)
    {
        NSLog(@"[getStaticCodeRef] failed to get URL to binary %@", binaryPath);
        return NULL;
    }
    
    SecStaticCodeRef codeRef = NULL;
    OSStatus result;
    
    result = SecStaticCodeCreateWithPathAndAttributes(binaryURL, kSecCSDefaultFlags, NULL, &codeRef);
    
    CFRelease(binaryURL);
    
    if(result != errSecSuccess)
    {
        NSLog(@"[getStaticCodeRef] failed to create static code for binary %@", binaryPath);
        return NULL;
    }
        
    return codeRef;
}

NSDictionary* dumpEntitlements(SecStaticCodeRef codeRef)
{
    if(codeRef == NULL)
    {
        NSLog(@"[dumpEntitlements] attempting to dump entitlements without a StaticCodeRef");
        return nil;
    }
    
    CFDictionaryRef signingInfo = NULL;
    OSStatus result;
    
    result = SecCodeCopySigningInformation(codeRef, kSecCSRequirementInformation, &signingInfo);
    
    if(result != errSecSuccess)
    {
        NSLog(@"[dumpEntitlements] failed to copy signing info from static code");
        return nil;
    }
    
    NSDictionary *entitlementsNSDict = nil;
    
    CFDictionaryRef entitlements = (CFDictionaryRef)CFDictionaryGetValue(signingInfo, kSecCodeInfoEntitlementsDict);
    if(entitlements == NULL)
    {
        NSLog(@"[dumpEntitlements] no entitlements specified");
    }
    else if(CFGetTypeID(entitlements) != CFDictionaryGetTypeID())
    {
        NSLog(@"[dumpEntitlements] invalid entitlements");
    }
    else
    {
        entitlementsNSDict = (__bridge NSDictionary *)(entitlements);
        // NSLog(@"[dumpEntitlements] dumped %@", entitlementsNSDict);
    }
    
    CFRelease(signingInfo);
    return entitlementsNSDict;
}

NSDictionary* dumpEntitlementsFromBinaryAtPath(NSString *binaryPath)
{
    // This function is intended for one-shot checks. Main-event functions should retain/release their own SecStaticCodeRefs
    
    if(binaryPath == nil)
    {
        return nil;
    }
    
    SecStaticCodeRef codeRef = getStaticCodeRef(binaryPath);
    if(codeRef == NULL)
    {
        return nil;
    }
    
    NSDictionary *entitlements = dumpEntitlements(codeRef);
    CFRelease(codeRef);

    return entitlements;
}

NSString* getTeamIDFromBinaryAtPath(NSString *binaryPath)
{
	SecStaticCodeRef codeRef = getStaticCodeRef(binaryPath);
	if(codeRef == NULL) {
		return nil;
	}
	
    CFDictionaryRef signingInfo = NULL;
    OSStatus result = SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingInfo);
    if(result != errSecSuccess) return nil;
        
    NSString* teamID = (NSString*)CFDictionaryGetValue(signingInfo, CFSTR("teamid"));
	
	CFRelease(signingInfo);
	CFRelease(codeRef);
	
	return teamID;
}

NSDictionary* infoDictionaryForAppPath(NSString* appPath)
{
	if(!appPath) return nil;
	NSString* infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	return [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
}

NSString* appMainExecutablePathForAppPath(NSString* appPath)
{
	if(!appPath) return nil;
	return [appPath stringByAppendingPathComponent:infoDictionaryForAppPath(appPath)[@"CFBundleExecutable"]];
}

BOOL isSameFile(NSString *path1, NSString *path2)
{
	struct stat sb1;
	struct stat sb2;
	stat(path1.fileSystemRepresentation, &sb1);
	stat(path2.fileSystemRepresentation, &sb2);
	return sb1.st_ino == sb2.st_ino;
}

BOOL isSubpathOf(NSString *subPath, NSString *parentPath) 
{
    NSURL *parentURL = [NSURL fileURLWithPath:parentPath].URLByStandardizingPath;
    NSURL *subURL = [NSURL fileURLWithPath:subPath].URLByStandardizingPath;

    NSArray<NSString *> *parentComponents = parentURL.pathComponents;
    NSArray<NSString *> *subComponents = subURL.pathComponents;

    if (subComponents.count < parentComponents.count) {
        return NO;
    }

    for (NSUInteger i = 0; i < parentComponents.count; i++) {
        if (![subComponents[i] isEqualToString:parentComponents[i]]) {
            return NO;
        }
    }

    return YES;
}

BOOL isMachoFile(NSString* filePath)
{
	bool ismacho=false, islib=false;
	machoGetInfo(filePath.fileSystemRepresentation, &ismacho, &islib);
	return ismacho;
}

NSArray* blockedResignBundles = @[
    @"com.apple.Safari.SandboxBroker",
];

int signApp(NSString* appPath)
{
	NSDictionary* baseEntitlements = nil;

	NSDictionary* appInfoDict = infoDictionaryForAppPath(appPath);
	if(!appInfoDict) return 172;


	if([appPath containsString:@"/Applications/"]) {
		//jailbroken apps or system apps

		baseEntitlements = [NSDictionary dictionaryWithContentsOfFile:jbroot(@"/basebin/entitlements/bootstrap.entitlements")];

	} else if(isRemovableBundlePath(appPath.fileSystemRepresentation)) {

		 if(hasTrollstoreMarker(appPath.fileSystemRepresentation))
		 {
			//trollstored apps
			baseEntitlements = [NSDictionary dictionaryWithContentsOfFile:jbroot(@"/basebin/entitlements/bootstrap.entitlements")];
		 } else {
			baseEntitlements = @{@"get-task-allow":@YES};
		 }

	}

	assert(baseEntitlements != nil);


	NSString* mainExecutablePath = appMainExecutablePathForAppPath(appPath);
	if(!mainExecutablePath) return 176;

	if(![[NSFileManager defaultManager] fileExistsAtPath:mainExecutablePath]) return 174;

	BOOL encryptedApp = [[NSFileManager defaultManager] fileExistsAtPath:[appPath stringByAppendingPathComponent:@"SC_Info"]];
	NSString* appTeamID = getTeamIDFromBinaryAtPath(mainExecutablePath);

	NSURL* fileURL;
	NSDirectoryEnumerator *enumerator;

	NSMutableArray* blockedBundlePaths = [NSMutableArray new];
	NSMutableArray* signedMainExecutables = [NSMutableArray new];

	// Due to how the new CT bug works, in order for data containers to work properly we need to add the
	// com.apple.private.security.container-required=<bundle-identifier> entitlement to every binary inside a bundle
	// For this we will want to first collect info about all the bundles in the app by seeking for Info.plist files and adding the ent to the main binary
	enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appPath] includingPropertiesForKeys:@[NSURLIsRegularFileKey] options:0 errorHandler:nil];
	while(fileURL = [enumerator nextObject])
	{
		NSNumber *isFile=nil;
        [fileURL getResourceValue:&isFile forKey:NSURLIsRegularFileKey error:nil];
        if (!isFile || ![isFile boolValue]) continue;

		NSMutableDictionary* extraEntitlements = baseEntitlements.mutableCopy;

		NSString *filePath = fileURL.path;
		if ([filePath.lastPathComponent isEqualToString:@"Info.plist"]) {
			NSDictionary *infoDict = [NSDictionary dictionaryWithContentsOfFile:filePath];
			if (!infoDict) continue;

			NSString *bundleId = infoDict[@"CFBundleIdentifier"];
			NSString *bundleExecutable = infoDict[@"CFBundleExecutable"];
			if (!bundleId || !bundleExecutable || !bundleExecutable.length) continue;

			NSString* platformName = infoDict[@"DTPlatformName"];
			NSArray* supportedPlatforms = infoDict[@"CFBundleSupportedPlatforms"];

			if([blockedResignBundles containsObject:bundleId] || [platformName isEqualToString:@"watchos"] || [supportedPlatforms containsObject:@"WatchOS"]) {
				[blockedBundlePaths addObject:[filePath stringByDeletingLastPathComponent]];
				continue;
			}

			NSString *bundleMainExecutablePath = [[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:bundleExecutable];
			if (![[NSFileManager defaultManager] fileExistsAtPath:bundleMainExecutablePath]) continue;

			NSString *packageType = infoDict[@"CFBundlePackageType"];

			// We don't care about frameworks (yet)
			if ([packageType isEqualToString:@"FMWK"]) continue;

			NSMutableDictionary *entitlementsToUse = dumpEntitlementsFromBinaryAtPath(bundleMainExecutablePath).mutableCopy;
			if (isSameFile(bundleMainExecutablePath, mainExecutablePath)) {
				// In the case where the main executable of the app currently has no entitlements at all
				// We want to ensure it gets signed with fallback entitlements
				// These mimic the entitlements that Xcodes gives every app it signs
				if (!entitlementsToUse) {
					entitlementsToUse = @{
						@"application-identifier" : @"TROLLTROLL.*",
						@"com.apple.developer.team-identifier" : @"TROLLTROLL",
						@"get-task-allow" : (__bridge id)kCFBooleanTrue,
						@"keychain-access-groups" : @[
							@"TROLLTROLL.*",
							@"com.apple.token"
						],
					}.mutableCopy;

					[extraEntitlements addEntriesFromDictionary:entitlementsToUse];
				}
			}
			else if(encryptedApp) {
				//only re-sign main executable for encrypted apps
				continue;
			}

			if (!entitlementsToUse) entitlementsToUse = [NSMutableDictionary new];


			BOOL containerRequired = YES;
			NSObject *containerRequiredObj = entitlementsToUse[@"com.apple.private.security.container-required"];
			if (containerRequiredObj && [containerRequiredObj isKindOfClass:[NSNumber class]]) {
				containerRequired = [(NSNumber *)containerRequiredObj boolValue];
				if(containerRequired) {
					NSLog(@"container %@ for %@", bundleId, filePath);
					extraEntitlements[@"com.apple.private.security.container-required"] = bundleId;
				}
			}

			if (!containerRequiredObj)
			{
				BOOL noContainer = NO;
				NSObject *noContainerObj = entitlementsToUse[@"com.apple.private.security.no-container"];
				if (noContainerObj && [noContainerObj isKindOfClass:[NSNumber class]]) {
					noContainer = [(NSNumber *)noContainerObj boolValue];
				}

				BOOL noSandbox = NO;
				NSObject *noSandboxObj = entitlementsToUse[@"com.apple.private.security.no-sandbox"];
				if (noSandboxObj && [noSandboxObj isKindOfClass:[NSNumber class]]) {
					noSandbox = [(NSNumber *)noSandboxObj boolValue];
				}

				if(!noContainer && !noSandbox) {
					// NSLog(@"container %@ for %@", bundleId, filePath);
					extraEntitlements[@"com.apple.private.security.container-required"] = bundleId;
				}
			}

			NSString* specialEntitlementsPath = jbroot([NSString stringWithFormat:@"/basebin/entitlements/bundles/%@.extra", bundleId]);
			if([NSFileManager.defaultManager fileExistsAtPath:specialEntitlementsPath])
				extraEntitlements = [NSMutableDictionary dictionaryWithContentsOfFile:specialEntitlementsPath];

			NSData *entitlementsXML = [NSPropertyListSerialization dataWithPropertyList:extraEntitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
			NSString* entitlementsString = [[NSString alloc] initWithData:entitlementsXML encoding:NSUTF8StringEncoding];


			NSString* stripEntitlements = nil;
			NSString* stripEntitlementsPath = jbroot([NSString stringWithFormat:@"/basebin/entitlements/bundles/%@.strip", bundleId]);
			if([NSFileManager.defaultManager fileExistsAtPath:stripEntitlementsPath])
				stripEntitlements = [NSString stringWithContentsOfFile:stripEntitlementsPath encoding:NSUTF8StringEncoding error:nil];

			assert(realstore(bundleMainExecutablePath.UTF8String, entitlementsString.UTF8String, stripEntitlements.UTF8String, appTeamID.UTF8String) == 0);
			[signedMainExecutables addObject:bundleMainExecutablePath];
		}
	}

	enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appPath] includingPropertiesForKeys:@[NSURLIsRegularFileKey] options:0 errorHandler:nil];
	while(fileURL = [enumerator nextObject])
	{
		NSNumber *isFile=nil;
        [fileURL getResourceValue:&isFile forKey:NSURLIsRegularFileKey error:nil];
        if (!isFile || ![isFile boolValue]) continue;

		if(encryptedApp) {
			//only re-sign main executable for encrypted apps
			continue;
		}

		BOOL blockedFile=NO;
		for(NSString* blockedBundlePath in blockedBundlePaths) {
			if(isSubpathOf(fileURL.path, blockedBundlePath)) {
				// NSLog(@"skip blocked bundle %@", fileURL);
				blockedFile=YES;
				break;
			}
		}
		if(blockedFile) continue;

		BOOL signedFile=NO;
		for(NSString* signedExecutable in signedMainExecutables) {
			if(isSameFile(signedExecutable, fileURL.path)) {
				//NSLog(@"skip signed %@", fileURL);
				signedFile=YES;
				break;
			}
		}
		if(signedFile) continue;

		if(!isMachoFile(fileURL.path)) continue;

		NSData *entitlementsXML = [NSPropertyListSerialization dataWithPropertyList:baseEntitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
		NSString* entitlementsString = [[NSString alloc] initWithData:entitlementsXML encoding:NSUTF8StringEncoding];

		assert(realstore(fileURL.path.UTF8String, entitlementsString.UTF8String, NULL, appTeamID.UTF8String) == 0);
	}

	return 0;
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		if(argc < 2) {
			printf("Usage: %s <path to app bundle or executable> [TeamID]\n", getprogname());
			return 1;
		}

        BOOL isDirectory = NO;
		if(![NSFileManager.defaultManager fileExistsAtPath:@(argv[1]) isDirectory:&isDirectory]) {
			printf("Can not access to '%s'\n", argv[1]);
			return 1;
		}

		return isDirectory ? signApp(@(argv[1])) : realstore(argv[1], NULL, NULL, argv[2]);
	}
}
