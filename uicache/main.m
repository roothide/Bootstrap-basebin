#import <Foundation/Foundation.h>
#import <Foundation/NSURL.h>
#import <dlfcn.h>
#import <getopt.h>
#import <stdio.h>
#include <spawn.h>
#include <sys/stat.h>
#include <objc/runtime.h>
#include <roothide.h>

#include "../bootstrapd/libbsd.h"

#define APP_PATH	@"/Applications"

#if NLS
#	include <libintl.h>
#	define _(a) gettext(a)
#	define PACKAGE "uikittools-ng"
#else
#	define _(a) a
#endif

#ifndef LOCALEDIR
#	define LOCALEDIR "/usr/share/locale"
#endif

@interface _LSApplicationState : NSObject
- (BOOL)isValid;
@end

@interface LSBundleProxy : NSObject
-(BOOL)isContainerized;
- (NSURL *)bundleURL;
- (NSURL *)containerURL;
- (NSURL *)dataContainerURL;
- (NSString *)bundleExecutable;
- (NSString *)bundleIdentifier;
@end

@interface LSPlugInKitProxy : LSBundleProxy
@end

@interface LSApplicationProxy : LSBundleProxy
+ (id)applicationProxyForIdentifier:(id)arg1;
- (id)localizedNameForContext:(id)arg1;
- (_LSApplicationState *)appState;
- (NSString *)vendorName;
- (NSString *)teamID;
- (NSString *)applicationType;
- (NSSet *)claimedURLSchemes;
- (BOOL)isDeletable;
- (NSDictionary*)environmentVariables;
@property (nonatomic,readonly) NSDictionary *groupContainerURLs;
@property (nonatomic,readonly) NSArray<LSPlugInKitProxy *> *plugInKitPlugins;
@end

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (BOOL)_LSPrivateRebuildApplicationDatabasesForSystemApps:(BOOL)arg1
												  internal:(BOOL)arg2
													  user:(BOOL)arg3;
- (BOOL)registerApplicationDictionary:(NSDictionary *)applicationDictionary;
- (BOOL)registerBundleWithInfo:(NSDictionary *)bundleInfo
					   options:(NSDictionary *)options
						  type:(unsigned long long)arg3
					  progress:(id)arg4;
- (BOOL)registerApplication:(NSURL *)url;
- (BOOL)registerPlugin:(NSURL *)url;
- (BOOL)unregisterApplication:(NSURL *)url;
- (NSArray *)installedPlugins;
- (void)_LSPrivateSyncWithMobileInstallation;
- (NSArray<LSApplicationProxy *> *)allApplications;
@end

typedef NS_OPTIONS(NSUInteger, SBSRelaunchActionOptions) {
	SBSRelaunchActionOptionsNone,
	SBSRelaunchActionOptionsRestartRenderServer = 1 << 0,
	SBSRelaunchActionOptionsSnapshotTransition = 1 << 1,
	SBSRelaunchActionOptionsFadeToBlackTransition = 1 << 2
};

@interface MCMContainer : NSObject

-(id)destroyContainerWithCompletion:(/*^block*/id)arg1 ;

+ (instancetype)containerWithIdentifier:(NSString *)identifier
					  createIfNecessary:(BOOL)createIfNecessary
								existed:(BOOL *)existed
								  error:(NSError **)error;
- (NSURL *)url;
@end

@interface MCMAppDataContainer : MCMContainer
@end

@interface MCMPluginKitPluginDataContainer : MCMContainer
@end

@interface MCMSystemDataContainer : MCMContainer
@end

@interface MCMSharedDataContainer : MCMContainer
@end

@interface SBSRelaunchAction : NSObject
+ (instancetype)actionWithReason:(NSString *)reason
						 options:(SBSRelaunchActionOptions)options
					   targetURL:(NSURL *)targetURL;
@end

@interface FBSSystemService : NSObject
+ (instancetype)sharedService;
- (void)sendActions:(NSSet *)actions withResult:(id)result;
@end

@interface PBSSystemService : NSObject
+ (instancetype)sharedInstance;
- (void)relaunch;
@end

typedef struct __SecCode const *SecStaticCodeRef;

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
	kSecCSDefaultFlags = 0
};
#define kSecCSRequirementInformation 1 << 2
#define kSecCSSigningInformation 1 << 1

OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *information);
CFDataRef SecCertificateCopyExtensionValue(SecCertificateRef certificate, CFTypeRef extensionOID, bool *isCritical);
void SecPolicySetOptionsValue(SecPolicyRef policy, CFStringRef key, CFTypeRef value);

extern CFStringRef kSecCodeInfoEntitlementsDict;
extern CFStringRef kSecCodeInfoCertificates;
extern CFStringRef kSecPolicyAppleiPhoneApplicationSigning;
extern CFStringRef kSecPolicyAppleiPhoneProfileApplicationSigning;
extern CFStringRef kSecPolicyLeafMarkerOid;

int force = 0;
int verbose = 0;

void help(void) {
	printf(_("Usage: %s [-afhlr] [-i id] [-p path] [-u path]\n\
Modified work Copyright (C) 2021, Procursus Team. All Rights Reserved.\n\n"), getprogname());
	printf(_("Update iOS registered applications and optionally restart SpringBoard\n\n"));

	printf(_("  -a, --all                Update all system and internal applications\n"));
	printf(_("  -f, --force              Force -a to reregister all Applications\n\
							  and modify App Store apps\n"));
	printf(_("  -p, --path <path>        Update application bundle at the specified path\n"));
	printf(_("  -s, --force-system       When registering an app with path /var/containers/Bundle/Application/<UUID>/*.app, register it as system\n"));
	printf(_("  -u, --unregister <path>  Unregister application bundle at the specified path\n"));
	printf(_("  -r, --respring           Restart SpringBoard and backboardd after\n\
							  updating applications\n"));
	printf(_("  -l, --list               List the bundle ids of installed apps\n"));
	printf(_("  -i, --info <bundleid>    Give information about given bundle id\n"));
	printf(_("  -h, --help               Give this help list.\n\n"));

	printf(_("Contact the Procursus Team for support.\n"));
}

SecStaticCodeRef getStaticCodeRef(NSString *binaryPath) {
	if (binaryPath == nil) {
		return NULL;
	}
	
	CFURLRef binaryURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (__bridge CFStringRef)binaryPath, kCFURLPOSIXPathStyle, false);
	if (binaryURL == NULL) {
		return NULL;
	}
	
	SecStaticCodeRef codeRef = NULL;
	OSStatus result;
	
	result = SecStaticCodeCreateWithPathAndAttributes(binaryURL, kSecCSDefaultFlags, NULL, &codeRef);
	
	CFRelease(binaryURL);
	
	if (result != errSecSuccess) {
		return NULL;
	}
		
	return codeRef;
}

NSDictionary *dumpEntitlements(SecStaticCodeRef codeRef) {
	if (codeRef == NULL) {
		return nil;
	}
	
	CFDictionaryRef signingInfo = NULL;
	OSStatus result;
	
	result = SecCodeCopySigningInformation(codeRef, kSecCSRequirementInformation, &signingInfo);
	
	if (result != errSecSuccess) {
		return nil;
	}
	
	NSDictionary *entitlementsNSDict = nil;
	
	CFDictionaryRef entitlements = CFDictionaryGetValue(signingInfo, kSecCodeInfoEntitlementsDict);
	if (entitlements) {
		if (CFGetTypeID(entitlements) == CFDictionaryGetTypeID()) {
			entitlementsNSDict = (__bridge NSDictionary *)(entitlements);
		}
	}
	CFRelease(signingInfo);
	return entitlementsNSDict;
}

NSDictionary *dumpEntitlementsFromBinaryAtPath(NSString *binaryPath) {
	if (binaryPath == nil) {
		return nil;
	}
	
	SecStaticCodeRef codeRef = getStaticCodeRef(binaryPath);
	if (codeRef == NULL) {
		return nil;
	}
	
	NSDictionary *entitlements = dumpEntitlements(codeRef);
	CFRelease(codeRef);

	return entitlements;
}

NSDictionary *constructGroupsContainersForEntitlements(NSDictionary *entitlements, BOOL systemGroups) {
	if (!entitlements) return nil;

	NSString *entitlementForGroups;
	Class mcmClass;
	if (systemGroups) {
		entitlementForGroups = @"com.apple.security.system-groups";
		mcmClass = [MCMSystemDataContainer class];
	}
	else {
		entitlementForGroups = @"com.apple.security.application-groups";
		mcmClass = [MCMSharedDataContainer class];
	}

	NSArray *groupIDs = entitlements[entitlementForGroups];
	if (groupIDs && [groupIDs isKindOfClass:[NSArray class]]) {
		NSMutableDictionary *groupContainers = [NSMutableDictionary new];

		for (NSString *groupID in groupIDs) {
			MCMContainer *container = [mcmClass containerWithIdentifier:groupID createIfNecessary:YES existed:nil error:nil];
			if (container.url) {
				groupContainers[groupID] = container.url.path;
			}
		}

		return groupContainers.copy;
	}

	return nil;
}

BOOL constructContainerizationForEntitlements(NSString* bundleId, NSString* path, NSDictionary *entitlements) {

	//hack way for "unsandbox but with a data container", so File Provider and Backup service can work for the jailbroken app
	NSNumber *hackContainer = entitlements[@"uicache.data-container-required"] ?: entitlements[@"uicache.app-data-container-required"];
	if (hackContainer && [hackContainer isKindOfClass:[NSNumber class]]) {
		if (hackContainer.boolValue) {
			return YES;
		}
	}
	
	//container-required: valid true/false, as first order, will ignore no-container and no-sandbox
	NSObject *containerRequired = entitlements[@"com.apple.private.security.container-required"];
	if (containerRequired && [containerRequired isKindOfClass:[NSNumber class]]) {
		return [(NSNumber*)containerRequired boolValue];
	}else if (containerRequired && [containerRequired isKindOfClass:[NSString class]]) {
		/* this feature is only supported by the kernel sandbox.framework, lsd does not make any special treatment for this.
			and no matter what type of bundle the executable belongs to, the process will always get an app-data-container(/var/mobile/Containers/Data/Application/) from sandbox.framework
		*/
		return YES;
	}

	//no-container: only valid true
	NSNumber *noContainer = entitlements[@"com.apple.private.security.no-container"];
	if (noContainer && [noContainer isKindOfClass:[NSNumber class]]) {
		if (noContainer.boolValue) {
			return NO;
		}
	}
	
	//no-sandbox: only valid true
	NSNumber *noSandbox = entitlements[@"com.apple.private.security.no-sandbox"];
	if (noSandbox && [noSandbox isKindOfClass:[NSNumber class]]) {
		if (noSandbox.boolValue) {

			if([bundleId hasPrefix:@"com.apple."]) //only hack for system apps, otherwise it may conflict with Patcher
			{
				NSNumber*AppDataContainers = entitlements[@"com.apple.private.security.storage.AppDataContainers"];
				if (AppDataContainers && [AppDataContainers isKindOfClass:[NSNumber class]]) {
					if (AppDataContainers.boolValue) return YES; //hack way
				}
			}

			return NO;
		}
	}

	// //app-sandbox: invalid
	// NSNumber *appSandbox = entitlements[@"com.apple.security.app-sandbox"];
	// if (appSandbox && [appSandbox isKindOfClass:[NSNumber class]]) {
	//
	// }

	// executables in containers/Bundle/ are always containerized by default
	if([path.stringByStandardizingPath hasPrefix:@"/var/containers/Bundle/"])
		return YES;

	return NO; // executables in other paths such rootfs/preboot/var will not be containerized by default
}

NSString *constructTeamIdentifierForEntitlements(NSDictionary *entitlements) {
	NSString *teamIdentifier = entitlements[@"com.apple.developer.team-identifier"];
	if (teamIdentifier && [teamIdentifier isKindOfClass:[NSString class]]) {
		return teamIdentifier;
	}
	return nil;
}

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


void* _CTServerConnectionCreate(CFAllocatorRef, void *, void *);
int64_t _CTServerConnectionSetCellularUsagePolicy(CFTypeRef* ct, NSString* identifier, NSDictionary* policies);

int networkFix(NSString* bundleIdentifier)
{
	return _CTServerConnectionSetCellularUsagePolicy(
		_CTServerConnectionCreate(kCFAllocatorDefault, NULL, NULL),
		bundleIdentifier,
		@{
			@"kCTCellularDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow",
			@"kCTWiFiDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow"
		}
	);
}


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
	@"com.opa334.CraneApplication.CraneShortcuts",
];

NSArray* patchRequiredAppPlugins = @[
    @"com.apple.shortcuts.Run-Workflow",
];

NSArray* appleInternalIdentifiers = @[
	@"com.apple.Terminal",
];


//sometimes launching the app may lose those environment variables(if not being containerized in lsd registry?)
NSDictionary *constructEnvironmentVariablesForContainerPath(NSString *mainBundleIdentifier, NSString *mainBundlePath, NSString *containerPath, BOOL isContainerized) 
{
	BOOL using_jbroot = YES;

	//Ignore the app from trollstore as TrollStore will reset its data container path when rebuilding icon cache
	//and its home directory will be redirected to jbroot by bootstrap.dylib (if tweak enabled)
	if([NSFileManager.defaultManager fileExistsAtPath:[mainBundlePath stringByAppendingString:@"/../_TrollStore"]]
		|| [NSFileManager.defaultManager fileExistsAtPath:[mainBundlePath stringByAppendingString:@"/../_TrollStoreLite"]]) {
		using_jbroot = NO;
	} else if(![NSFileManager.defaultManager fileExistsAtPath:[mainBundlePath stringByAppendingPathComponent:@".jbroot"]]) {
		using_jbroot = NO;
	} else if([mainBundleIdentifier hasPrefix:@"com.apple."] && ![appleInternalIdentifiers containsObject:mainBundleIdentifier]) {
		using_jbroot = NO;
	}

	NSString *homeDir = isContainerized ? containerPath : (using_jbroot ? jbroot(@"/var/mobile") : @"/var/mobile");
	NSString *tmpDir = isContainerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : (using_jbroot ? jbroot(@"/var/tmp") : @"/var/tmp");
	return @{
		@"CFFIXED_USER_HOME" : homeDir,
		@"HOME" : homeDir,
		@"TMPDIR" : tmpDir
	}.mutableCopy;
}

int execBinary(const char* path, char** argv)
{
	pid_t pid=0;
	int ret = posix_spawn(&pid, path, NULL, NULL, (char* const*)argv, /*environ* ignore preload lib*/ NULL);
	if(ret != 0) {
		return -1;
	}

	int status=0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        //keep waiting?return status;
    };

	return -1;
}

int spawner(NSString* executablePath)
{
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);

	pid_t pid=0;
	char* args[] = {(char*)executablePath.UTF8String,(char*)executablePath.UTF8String,NULL};
	int ret = posix_spawn(&pid, args[0], NULL, &attr, args, NULL);
	if(ret != 0) {
		NSLog(@"Error: %d %s", ret, strerror(ret));
		return -1;
	}
	if(pid) kill(pid, SIGKILL);
	NSLog(@"pid: %d of %@", pid, executablePath);
	return 0;
}

void activator(NSString* bundlePath)
{
	NSFileManager* fm = NSFileManager.defaultManager;

	NSDirectoryEnumerator* enumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:bundlePath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
	for(NSURL*fileURL in enumerator)
	{
		NSString *filePath = fileURL.path;
		if ([filePath.lastPathComponent isEqualToString:@"Info.plist"]) 
        {
            if(![fm fileExistsAtPath:[[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"SC_Info"]])
                continue;

			NSDictionary *infoDict = [NSDictionary dictionaryWithContentsOfFile:filePath];
			if (!infoDict) continue;

			NSString *bundleId = infoDict[@"CFBundleIdentifier"];
			NSString *bundleExecutable = infoDict[@"CFBundleExecutable"];
			if (!bundleId || !bundleExecutable || !bundleExecutable.length) continue;

			if ([infoDict[@"CFBundlePackageType"] isEqualToString:@"FMWK"]) continue;

			NSString *bundleMainExecutablePath = [[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:bundleExecutable];
			if (![fm fileExistsAtPath:bundleMainExecutablePath]) continue;


			// if ([infoDict[@"NSExtension"][@"NSExtensionPointIdentifier"] isEqualToString:@"com.apple.widget-extension"]) continue;
            
			NSLog(@"bundle=%@ type=%@", bundleId, infoDict[@"NSExtension"][@"NSExtensionPointIdentifier"]);

			if ([infoDict[@"CFBundlePackageType"] isEqualToString:@"APPL"]) {
				spawner(bundleMainExecutablePath);
			} else {
				spawner(bundleMainExecutablePath);
			}
        }
    }
}

void freeplay(NSString* mainBundleId, NSString* bundlePath)
{
    NSFileManager* fm = NSFileManager.defaultManager;

    if(![fm fileExistsAtPath:[bundlePath stringByAppendingPathExtension:@"appbackup"]])
        return;

    if(![fm fileExistsAtPath:[bundlePath stringByAppendingPathComponent:@"SC_Info"]])
        return;

    assert([fm moveItemAtPath:bundlePath toPath:[bundlePath stringByAppendingPathExtension:@"tmp"] error:nil]);
    assert([fm moveItemAtPath:[bundlePath stringByAppendingPathExtension:@"appbackup"] toPath:bundlePath error:nil]);

	activator(bundlePath);

    assert([fm moveItemAtPath:bundlePath toPath:[bundlePath stringByAppendingPathExtension:@"appbackup"] error:nil]);
    assert([fm moveItemAtPath:[bundlePath stringByAppendingPathExtension:@"tmp"] toPath:bundlePath error:nil]);

	activator(bundlePath);
}

int patchonly=0;

void registerPath(NSString *path, BOOL forceSystem)
{
	const char* sbtoken = bsd_getsbtoken();
	assert(sbtoken != NULL);

	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];

	path = path.stringByResolvingSymlinksInPath.stringByStandardizingPath;

	NSString* appInfoPath = [path stringByAppendingPathComponent:@"Info.plist"];
	NSMutableDictionary *appInfoPlist = [NSMutableDictionary dictionaryWithContentsOfFile:appInfoPath];
	NSData* appInfoData = [NSData dataWithContentsOfFile:appInfoPath];

	NSString *appBundleID = [appInfoPlist objectForKey:@"CFBundleIdentifier"];

	if(!appBundleID) {
		fprintf(stderr, _("Error: Unable to parse app %s\n"), path.fileSystemRepresentation);
		return;
	}

	NSString *appExecutablePath = [path stringByAppendingPathComponent:appInfoPlist[@"CFBundleExecutable"]];

	BOOL allowURLSchemes = [NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/var/mobile/.allow_url_schemes")];

	if(!allowURLSchemes)
	{
		//NSLog(@"Info=%@", appInfoPlist);
		NSMutableArray* urltypes = [appInfoPlist[@"CFBundleURLTypes"] mutableCopy];
		for(int i=0; i<urltypes.count; i++) {
		//NSLog(@"schemes=%@", urltypes[i][@"CFBundleURLSchemes"]);
			
			NSMutableArray* schemes = [urltypes[i][@"CFBundleURLSchemes"] mutableCopy];
			[schemes removeObjectsInArray:blockedURLSchemes];
			//NSLog(@"new schemes=%@", schemes);

			if(![appBundleID isEqualToString:@"com.apple.Preferences"] && [schemes containsObject:@"prefs"])
				[schemes removeObject:@"prefs"];

			urltypes[i][@"CFBundleURLSchemes"] = schemes.copy;
		}
		appInfoPlist[@"CFBundleURLTypes"] = urltypes.copy;
	}

    BOOL isAppleBundle = [appBundleID hasPrefix:@"com.apple."];

	NSString* executableName = appInfoPlist[@"CFBundleExecutable"];
	// if([executableName hasPrefix:@"."]) executableName = [executableName substringFromIndex:1];

	NSString* jbrootpath = [path stringByAppendingPathComponent:@".jbroot"];
	BOOL jbrootexists = [NSFileManager.defaultManager fileExistsAtPath:jbrootpath];

	//try
	unlink([path stringByAppendingPathComponent:@".preload"].UTF8String);
	unlink([path stringByAppendingPathComponent:@".prelib"].UTF8String);
	
	NSString* rebuildFile = [path stringByAppendingPathComponent:@".rebuild"];

	if(jbrootexists)
	{
		if(!isAppleBundle
			 && ![NSFileManager.defaultManager fileExistsAtPath:[path stringByAppendingString:@"/../_TrollStore"]]
			  && ![NSFileManager.defaultManager fileExistsAtPath:[path stringByAppendingString:@"/../_TrollStoreLite"]])
		{
			freeplay(appBundleID, path);
		}

		BOOL requiredRebuild = NO;

		NSMutableDictionary* rebuildStatus = [NSMutableDictionary dictionaryWithContentsOfFile:rebuildFile];

		struct stat st={0};
		if(stat(appExecutablePath.fileSystemRepresentation, &st) == 0)
		{
			requiredRebuild = YES;

			if(rebuildStatus 
				//dev may change after reboot// && [rebuildStatus[@"st_dev"] longValue]==st.st_dev
				&& [rebuildStatus[@"st_ino"] unsignedLongLongValue]==st.st_ino
				&& [rebuildStatus[@"st_mtime"] longValue]==st.st_mtimespec.tv_sec 
				&& [rebuildStatus[@"st_mtimensec"] longValue]==st.st_mtimespec.tv_nsec) {
				requiredRebuild = NO;
			} else {
				// NSLog(@"rebuild %ld,%d,%llu,%llu / %ld:%ld %ld:%ld", 
				// [rebuildStatus[@"st_dev"] longValue], st.st_dev
				// , [rebuildStatus[@"st_ino"] unsignedLongLongValue], st.st_ino
				// , [rebuildStatus[@"st_mtime"] longValue], st.st_mtimespec.tv_sec 
				// , [rebuildStatus[@"st_mtimensec"] longValue], st.st_mtimespec.tv_nsec);
			}
		}

		if(!rebuildStatus) rebuildStatus = [NSMutableDictionary new];

		if(requiredRebuild)
		{
			//NSLog(@"patch macho: %@", appExecutablePath);
			int patch_app_exe(const char* file);
			assert(patch_app_exe(appExecutablePath.UTF8String)==0);

			char* argv[] = {"/basebin/rebuildapp", (char*)rootfs(path).UTF8String, NULL};
			assert(execBinary(jbroot(argv[0]), argv) == 0);
			
			assert(stat(appExecutablePath.fileSystemRepresentation, &st) == 0); //update mtime

			[rebuildStatus addEntriesFromDictionary:@{
				@"st_dev":@(st.st_dev), 
				@"st_ino":@(st.st_ino), 
				@"st_mtime":@(st.st_mtimespec.tv_sec), 
				@"st_mtimensec":@(st.st_mtimespec.tv_nsec),
				@"sb_token":@(sbtoken)
			}];
		}

		[rebuildStatus addEntriesFromDictionary:@{@"sb_token":@(sbtoken)}];
		assert([rebuildStatus writeToFile:rebuildFile atomically:YES]);

		// NSString* newExecutableName = @".preload";
		// appInfoPlist[@"CFBundleExecutable"] = newExecutableName;

		appInfoPlist[@"SBAppUsesLocalNotifications"] = @1;

		link(jbroot("/basebin/preload"), [path stringByAppendingPathComponent:@".preload"].UTF8String);
		link(jbroot("/basebin/preload.dylib"), [path stringByAppendingPathComponent:@".prelib"].UTF8String);
	}
	else
	{
		unlink(rebuildFile.UTF8String);
	}

    if(!isAppleBundle) {
        [appInfoPlist writeToFile:appInfoPath atomically:YES];
    }

	BOOL isRemovableSystemApp = [[NSFileManager defaultManager] fileExistsAtPath:[@"/System/Library/AppSignatures" stringByAppendingPathComponent:appBundleID]];
	BOOL registerAsUser = isDefaultInstallationPath(path) && !isRemovableSystemApp && !forceSystem;

	NSMutableDictionary *dictToRegister = [NSMutableDictionary dictionary];

	// Add entitlements
	NSDictionary *entitlements = dumpEntitlementsFromBinaryAtPath(appExecutablePath);
	if (entitlements) {
		dictToRegister[@"Entitlements"] = entitlements;
	}

	// Misc

	dictToRegister[@"ApplicationType"] = registerAsUser ? @"User" : @"System";
	dictToRegister[@"CFBundleIdentifier"] = appBundleID;
	dictToRegister[@"CodeInfoIdentifier"] = appBundleID;
	dictToRegister[@"CompatibilityState"] = @0;

	BOOL appContainerized = constructContainerizationForEntitlements(appBundleID, path, entitlements);
	dictToRegister[@"IsContainerized"] = @(appContainerized);
	if (appContainerized) {
		MCMContainer *appContainer = [NSClassFromString(@"MCMAppDataContainer") containerWithIdentifier:appBundleID createIfNecessary:YES existed:nil error:nil];
		NSString *containerPath = [appContainer url].path;

		dictToRegister[@"Container"] = containerPath; /*
		if app executable using another container in entitlements, 
		lsd still create the app-bundle-id container for EnvironmentVariables but set Container-Path to  /var/mobile,  
		when executable  actually runs, the kernel sandbox framework will ask the containerermanagerd to get the container defined in entitlements */
		dictToRegister[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(appBundleID, path, containerPath, YES);
	} else {
		dictToRegister[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(appBundleID, path, nil, NO);
	}

	dictToRegister[@"IsDeletable"] = @(registerAsUser || isRemovableSystemApp || isDefaultInstallationPath(path));
	dictToRegister[@"Path"] = path;
	
	dictToRegister[@"SignerOrganization"] = @"Apple Inc.";
	dictToRegister[@"SignatureVersion"] = @0x20500;
	dictToRegister[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";
	dictToRegister[@"IsAdHocSigned"] = @YES;
	dictToRegister[@"LSInstallType"] = @1;
	dictToRegister[@"HasMIDBasedSINF"] = @0;
	dictToRegister[@"MissingSINF"] = @0;
	dictToRegister[@"FamilyID"] = @0;
	dictToRegister[@"IsOnDemandInstallCapable"] = @0;

	NSString *teamIdentifier = constructTeamIdentifierForEntitlements(entitlements);
	if (teamIdentifier) dictToRegister[@"TeamIdentifier"] = teamIdentifier;

	// Add group containers

	NSDictionary *appGroupContainers = constructGroupsContainersForEntitlements(entitlements, NO);
	NSDictionary *systemGroupContainers = constructGroupsContainersForEntitlements(entitlements, YES);
	NSMutableDictionary *groupContainers = [NSMutableDictionary new];
	[groupContainers addEntriesFromDictionary:appGroupContainers];
	[groupContainers addEntriesFromDictionary:systemGroupContainers];
	if (groupContainers.count) {
		if (appGroupContainers.count) {
			dictToRegister[@"HasAppGroupContainers"] = @YES;
		}
		if (systemGroupContainers.count) {
			dictToRegister[@"HasSystemGroupContainers"] = @YES;
		}
		dictToRegister[@"GroupContainers"] = groupContainers.copy;
	}

	// Add plugins

	NSString *pluginsPath = [path stringByAppendingPathComponent:@"PlugIns"];
	NSArray *plugins = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginsPath error:nil];

	NSMutableDictionary *bundlePlugins = [NSMutableDictionary dictionary];
	for (NSString *pluginName in plugins) {
		NSString *pluginPath = [pluginsPath stringByAppendingPathComponent:pluginName];

		NSDictionary *pluginInfoPlist = [NSDictionary dictionaryWithContentsOfFile:[pluginPath stringByAppendingPathComponent:@"Info.plist"]];
		NSString *pluginBundleID = [pluginInfoPlist objectForKey:@"CFBundleIdentifier"];

		if (!pluginBundleID) continue;

		if(!allowURLSchemes && [blockedAppPlugins containsObject:pluginBundleID]) continue;


		NSMutableDictionary *pluginDict = [NSMutableDictionary dictionary];

		// Add entitlements

		NSString *pluginExecutablePath = [pluginPath stringByAppendingPathComponent:pluginInfoPlist[@"CFBundleExecutable"]];
		NSDictionary *pluginEntitlements = dumpEntitlementsFromBinaryAtPath(pluginExecutablePath);
		if (pluginEntitlements) {
			pluginDict[@"Entitlements"] = pluginEntitlements;
		}

		//try
		unlink([pluginPath stringByAppendingPathComponent:@".preload"].UTF8String);
		unlink([pluginPath stringByAppendingPathComponent:@".prelib"].UTF8String);
		unlink([pluginPath stringByAppendingPathComponent:@".jbroot"].UTF8String);

		NSString* rebuildFile = [pluginPath stringByAppendingPathComponent:@".rebuild"];
			
		if(jbrootexists && [patchRequiredAppPlugins containsObject:pluginBundleID] && pluginExecutablePath && pluginExecutablePath.length)
		{
			NSLog(@"patch app plugin: %@ %@", pluginBundleID, pluginExecutablePath);
			[NSFileManager.defaultManager copyItemAtPath:jbrootpath toPath:[pluginPath stringByAppendingPathComponent:@".jbroot"] error:nil];

			BOOL requiredRebuild = NO;
			NSMutableDictionary* rebuildStatus = [NSMutableDictionary dictionaryWithContentsOfFile:rebuildFile];

			struct stat st={0};
			if(stat(appExecutablePath.fileSystemRepresentation, &st) == 0)
			{
				requiredRebuild = YES;

				if(rebuildStatus 
					//dev may change after reboot// && [rebuildStatus[@"st_dev"] longValue]==st.st_dev
					&& [rebuildStatus[@"st_ino"] unsignedLongLongValue]==st.st_ino
					&& [rebuildStatus[@"st_mtime"] longValue]==st.st_mtimespec.tv_sec 
					&& [rebuildStatus[@"st_mtimensec"] longValue]==st.st_mtimespec.tv_nsec) {
					requiredRebuild = NO;
				} else {
					// NSLog(@"rebuild %ld,%d,%llu,%llu / %ld:%ld %ld:%ld", 
					// [rebuildStatus[@"st_dev"] longValue], st.st_dev
					// , [rebuildStatus[@"st_ino"] unsignedLongLongValue], st.st_ino
					// , [rebuildStatus[@"st_mtime"] longValue], st.st_mtimespec.tv_sec 
					// , [rebuildStatus[@"st_mtimensec"] longValue], st.st_mtimespec.tv_nsec);
				}
			}

			if(!rebuildStatus) rebuildStatus = [NSMutableDictionary new];

			if(requiredRebuild)
			{
				//NSLog(@"patch macho: %@", pluginExecutablePath);
				int patch_app_exe(const char* file);
				assert(patch_app_exe(pluginExecutablePath.UTF8String)==0);

				char* argv[] = {"/basebin/rebuildapp", "executable", (char*)rootfs(pluginExecutablePath).UTF8String, NULL};
				assert(execBinary(jbroot(argv[0]), argv) == 0);

				assert(stat(appExecutablePath.fileSystemRepresentation, &st) == 0); //update mtime

				[rebuildStatus addEntriesFromDictionary:@{
					@"st_dev":@(st.st_dev), 
					@"st_ino":@(st.st_ino), 
					@"st_mtime":@(st.st_mtimespec.tv_sec), 
					@"st_mtimensec":@(st.st_mtimespec.tv_nsec),
					@"sb_token":@(sbtoken)
				}];
			}

			[rebuildStatus addEntriesFromDictionary:@{@"sb_token":@(sbtoken)}];
			assert([rebuildStatus writeToFile:rebuildFile atomically:YES]);

			// NSString* newExecutableName = @".preload";
			// appInfoPlist[@"CFBundleExecutable"] = newExecutableName;

			link(jbroot("/basebin/preload"), [pluginPath stringByAppendingPathComponent:@".preload"].UTF8String);
			link(jbroot("/basebin/preload.dylib"), [pluginPath stringByAppendingPathComponent:@".prelib"].UTF8String);
		}
		else
		{
			unlink(rebuildFile.UTF8String);
		}

		// Misc

		pluginDict[@"ApplicationType"] = @"PluginKitPlugin";
		pluginDict[@"CFBundleIdentifier"] = pluginBundleID;
		pluginDict[@"CodeInfoIdentifier"] = pluginBundleID;
		pluginDict[@"CompatibilityState"] = @0;

		/* pkd requires that App PlugIns be containerized */
		BOOL pluginContainerized = YES;

		pluginDict[@"IsContainerized"] = @(pluginContainerized);
		MCMContainer *pluginContainer = [NSClassFromString(@"MCMPluginKitPluginDataContainer") containerWithIdentifier:pluginBundleID createIfNecessary:YES existed:nil error:nil];
		NSString *pluginContainerPath = [pluginContainer url].path;

		pluginDict[@"Container"] = pluginContainerPath;
		pluginDict[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(appBundleID, path, pluginContainerPath, pluginContainerized);

		pluginDict[@"Path"] = pluginPath;
		pluginDict[@"PluginOwnerBundleID"] = appBundleID;
		pluginDict[@"SignerOrganization"] = @"Apple Inc.";
		pluginDict[@"SignatureVersion"] = @132352;
		pluginDict[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";

		NSString *pluginTeamIdentifier = constructTeamIdentifierForEntitlements(pluginEntitlements);
		if (pluginTeamIdentifier) pluginDict[@"TeamIdentifier"] = pluginTeamIdentifier;

		// Add plugin group containers

		NSDictionary *pluginAppGroupContainers = constructGroupsContainersForEntitlements(pluginEntitlements, NO);
		NSDictionary *pluginSystemGroupContainers = constructGroupsContainersForEntitlements(pluginEntitlements, YES);
		NSMutableDictionary *pluginGroupContainers = [NSMutableDictionary new];
		[pluginGroupContainers addEntriesFromDictionary:pluginAppGroupContainers];
		[pluginGroupContainers addEntriesFromDictionary:pluginSystemGroupContainers];
		if (pluginGroupContainers.count) {
			if (pluginAppGroupContainers.count) {
				pluginDict[@"HasAppGroupContainers"] = @YES;
			}
			if (pluginSystemGroupContainers.count) {
				pluginDict[@"HasSystemGroupContainers"] = @YES;
			}
			pluginDict[@"GroupContainers"] = pluginGroupContainers.copy;
		}

		[bundlePlugins setObject:pluginDict forKey:pluginBundleID];
	}
	[dictToRegister setObject:bundlePlugins forKey:@"_LSBundlePlugins"];

	if (verbose) {
		printf("Registering dictionary: %s\n", dictToRegister.description.UTF8String);
	}

if(!patchonly) {
	if ([workspace registerApplicationDictionary:dictToRegister])
	{
		networkFix(appBundleID);
		for(NSString* pluginId in dictToRegister[@"_LSBundlePlugins"])
		{
			NSDictionary* pluginDict = dictToRegister[@"_LSBundlePlugins"][pluginId];
			networkFix(pluginDict[@"CFBundleIdentifier"]);
		}
	}
	else
	{
		fprintf(stderr, _("Error: Unable to register %s\n"), path.fileSystemRepresentation);
	}
}

    if(!isAppleBundle) {
        [appInfoData writeToFile:appInfoPath atomically:YES];
    }
}

void unregisterApp(NSString* arg)
{
	NSString* path = nil;

	if([arg containsString:@"/"]) {
		path = jbroot(arg);
	} else {
		LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:arg];
		if(app) path = app.bundleURL.path;
	}

	if(!path) {
		fprintf(stderr, _("Error: Unable to find bundle for %s\n"), arg.UTF8String);
		return;
	}

	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];

	NSURL* url = [NSURL fileURLWithPath:path];

	if (![workspace unregisterApplication:url]) {
		fprintf(stderr, _("Error: Unable to unregister"));
	}
}

void listBundleID(void) {
	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
	for (LSApplicationProxy *app in [workspace allApplications]) {
		printf("%s : %s\n", [[app bundleIdentifier] UTF8String], [[app bundleURL] fileSystemRepresentation]);
	}
}

void infoForBundleID(NSString *bundleID) {
	LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:bundleID];

	if ([[app appState] isValid]) {
		printf(_("Name: %s\n"), [[app localizedNameForContext:nil] UTF8String]);
		printf(_("Bundle Identifier: %s\n"), [[app bundleIdentifier] UTF8String]);
		printf(_("Executable Name: %s\n"), [[app bundleExecutable] UTF8String]);
		printf(_("Path: %s\n"), [[app bundleURL] fileSystemRepresentation]);
		printf(_("Container Path: %s\n"), [[app containerURL] fileSystemRepresentation]);
		printf(_("Data Container Path: %s\n"), [[app dataContainerURL] fileSystemRepresentation]);
		printf(_("Vendor Name: %s\n"), [[app vendorName] UTF8String]);
		printf(_("Team ID: %s\n"), [[app teamID] UTF8String]);
		printf(_("Type: %s\n"), [[app applicationType] UTF8String]);
		printf(_("Removable: %s\n"), [app isDeletable] ? _("true") : _("false"));
		printf(_("Containerized: %s\n"), [app isContainerized] ? _("true") : _("false"));

		for(NSString* name in [app environmentVariables])
			printf(_("EnvironmentVariables: %s = %s\n"), [name UTF8String], [[[app environmentVariables] objectForKey:name] UTF8String]);

		[app.groupContainerURLs enumerateKeysAndObjectsUsingBlock:^(NSString *groupID, NSURL *groupURL, BOOL *stop) {
			printf(_("Group Container: %s -> %s\n"), groupID.UTF8String, groupURL.fileSystemRepresentation);
		}];

		for(LSPlugInKitProxy *plugin in app.plugInKitPlugins) {
			NSURL* pluginURL = plugin.dataContainerURL;
			if(pluginURL) {
				printf(_("App Plugin Container: %s -> %s\n"), plugin.bundleIdentifier.UTF8String, pluginURL.fileSystemRepresentation);
			}
		}

		if ([app respondsToSelector:@selector(claimedURLSchemes)]) {
			for (NSString *scheme in [app claimedURLSchemes]) {
				printf(_("URL Scheme: %s\n"), [scheme UTF8String]);
			}
		} else {
			NSArray<NSDictionary *> *appURLs = [[NSBundle bundleWithURL:[app bundleURL]] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
			for (NSDictionary *urlInfo in appURLs) {
				for (NSString *urlScheme in urlInfo[@"CFBundleURLSchemes"]) {
					printf(_("URL Scheme: %s\n"), [urlScheme UTF8String]);
				}
			}
		}
	} else {
		printf(_("%s is an invalid bundle id\n"), [[app bundleIdentifier] UTF8String]);
	}
}

extern char*const* environ;

void registerAll(void) {
	if (force) {
		[[LSApplicationWorkspace defaultWorkspace] _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:NO];
		//rebuild will unregister all jailbroken apps, so we need to re-register them //return;
	}

	//installed jailbroken apps in disk
	NSMutableDictionary* installedApps = [[NSMutableDictionary alloc] init];

	NSURL *appsURL = [NSURL fileURLWithPath:jbroot(APP_PATH) isDirectory:YES];
	for (NSURL *appURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:appsURL includingPropertiesForKeys:nil options:0 error:nil]) {
		NSURL *infoPlistURL = [appURL URLByAppendingPathComponent:@"Info.plist"];
		NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL error:nil];
		if (infoPlist) {
			NSString* bundleID = infoPlist[@"CFBundleIdentifier"];
			if (bundleID) {
				// if([installedApps objectForKey:bundleID]) {
				// 	// duplicate app?
				// }
				installedApps[bundleID] = appURL;
			}
		}
	}

	//registered jailbroken apps in LSD
	NSMutableDictionary* registeredApps = [[NSMutableDictionary alloc] init];

	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
	for (LSApplicationProxy *app in [workspace allApplications]) {
		NSString *appPath = app.bundleURL.path;
		//printf("apppath=%s\n", appPath.UTF8String);
		//ios app default storage directory, others are jailbroken apps
		if ( ![appPath hasPrefix:@"/Applications/"]
			&& ![appPath hasPrefix:@"/Developer/Applications/"]
			&& !isDefaultInstallationPath(appPath)
			) {
			registeredApps[app.bundleIdentifier] = app.bundleURL;
		}
	}

	for (NSString* bundleID in installedApps)
	{
		//re-randomized jbroot everytime we jailbreak,
		//and don't re-register registered apps (may cause sileo get killed while installing apps) there is "uicache -a" in uikittools trigger
		if (![registeredApps objectForKey:bundleID]
			|| ![installedApps[bundleID] isEqual:registeredApps[bundleID]]
		) {
			NSString* bundlePath = [installedApps[bundleID] path];
			if (verbose) printf(_("registering %s : %s\n"), bundleID.UTF8String, bundlePath.UTF8String);
			
			pid_t pid;
			char *const args[] = {"/basebin/uicache", "-p", (char*)rootfs(bundlePath.UTF8String), NULL};
			assert(posix_spawn(&pid, jbroot(args[0]), NULL, NULL, args, environ) == 0);

			int status=0;
			while(waitpid(pid, &status, 0) != -1) {
				usleep(100*1000);
			};
			if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
				fprintf(stderr, _("Error: Failed to register %s\n"), bundlePath.UTF8String);
			}
		}
	}

	for (NSString *bundleID in registeredApps)
	{
		if (![installedApps objectForKey:bundleID])
		{
			NSString* bundlePath = [registeredApps[bundleID] path];
			if (verbose) printf(_("unregistering %s : %s\n"), bundleID.UTF8String, bundlePath.UTF8String);
			//using bundleID to unregister
			unregisterApp(bundleID);
		}
	}
}

int main(int argc, char *argv[]) {
	assert(geteuid() == 0);

#if NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	@autoreleasepool {
		BOOL all = NO;
		BOOL respring = NO;
		BOOL forceSystem = NO;
		NSMutableSet *registerSet = [[NSMutableSet alloc] init];
		NSMutableSet *unregisterSet = [[NSMutableSet alloc] init];
		BOOL list = NO;
		NSMutableSet *infoSet = [[NSMutableSet alloc] init];
		BOOL showHelp = NO;

		struct option longOptions[] = {
			{"all", no_argument, 0, 'a'},
			{"path", required_argument, 0, 'p'},
			{"force-system", no_argument, 0, 's'}, 
			{"unregister", required_argument, 0, 'u'},
			{"respring", no_argument, 0, 'r'},
			{"list", optional_argument, 0, 'l'},
			{"info", required_argument, 0, 'i'},
			{"help", no_argument, 0, 'h'},
			{"verbose", no_argument, 0, 'v'},	// verbose was added to maintain compatibility with old uikittools
			{"force", no_argument, 0, 'f'},
			{"patchonly", no_argument, 0, 0},
			{NULL, 0, NULL, 0}};

		int index = 0, code = 0;

		while ((code = getopt_long(argc, argv, "ap:u:rl::si:hfvn", longOptions, &index)) != -1) {
			switch (code) {
				case 0:
					if (strcmp(longOptions[index].name, "patchonly") == 0) {
						patchonly = 1;
					}
					break;
				case 'a':
					all = YES;
					break;
				case 'p':
					[registerSet addObject:[NSString stringWithUTF8String:strdup(optarg)]];
					break;
				case 's':
					forceSystem = YES;
					break;
				case 'u':
					[unregisterSet addObject:[NSString stringWithUTF8String:strdup(optarg)]];
					break;
				case 'r':
					respring = YES;
					break;
				case 'h':
					showHelp = YES;
					break;
				case 'l':
					if (optarg) {
						[infoSet addObject:[NSString stringWithUTF8String:strdup(optarg)]];
					}
					else if (NULL != argv[optind] && '-' != argv[optind][0]) {
						[infoSet addObject:[NSString stringWithUTF8String:strdup(argv[optind++])]];
					}
					else {
						list = YES;
					}
					break;
				case 'i':
					[infoSet addObject:[NSString stringWithUTF8String:strdup(optarg)]];
					break;
				case 'f':
					force = YES;
					break;
				case 'v':
					verbose = YES;
					break;
			}
		}

		if (showHelp || argc == 1) {
			help();
			return 0;
		}

		if (list) listBundleID();

		for (NSString *bundleID in infoSet) {
			infoForBundleID(bundleID);
		}

		for (NSString *path in registerSet) {
			registerPath(jbroot(path), forceSystem);
		}

		for (NSString *arg in unregisterSet) {
			unregisterApp(arg);
		}

		if (all) {
			registerAll();
		}

		if (respring) {
			dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
#if TARGET_OS_TV
		dlopen("/System/Library/PrivateFrameworks/PineBoardServices.framework/PineBoardServices", RTLD_NOW);
		[[objc_getClass("PBSSystemService") sharedInstance] relaunch];
#else
			dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);

			SBSRelaunchActionOptions restartOptions = (SBSRelaunchActionOptionsRestartRenderServer | SBSRelaunchActionOptionsFadeToBlackTransition);
			SBSRelaunchAction *restartAction = [objc_getClass("SBSRelaunchAction") actionWithReason:@"respring" options:restartOptions targetURL:nil];
			[(FBSSystemService *)[objc_getClass("FBSSystemService") sharedService] sendActions:[NSSet setWithObject:restartAction] withResult:nil];
#endif
			sleep(2);
		}

		return 0;
	}
}
