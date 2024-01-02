#import <Foundation/Foundation.h>
#import <Foundation/NSURL.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <dlfcn.h>
#import <getopt.h>
#import <objc/runtime.h>
#import <stdio.h>

#include <roothide.h>

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

@interface LSPlugInKitProxy : NSObject
- (NSString *)bundleIdentifier;
@property (nonatomic,readonly) NSURL *dataContainerURL;
@end

@interface LSApplicationProxy : NSObject
- (id)correspondingApplicationRecord;
+ (id)applicationProxyForIdentifier:(id)arg1;
- (id)localizedNameForContext:(id)arg1;
- (_LSApplicationState *)appState;
- (NSURL *)bundleURL;
- (NSURL *)containerURL;
- (NSString *)bundleExecutable;
- (NSString *)bundleIdentifier;
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

BOOL constructContainerizationForEntitlements(NSString* path, NSDictionary *entitlements, NSString** customContainerOut) {

	//container-required: valid true/false, as first order, will ignore no-container and no-sandbox
	NSObject *containerRequired = entitlements[@"com.apple.private.security.container-required"];
	if (containerRequired && [containerRequired isKindOfClass:[NSNumber class]]) {
		return [(NSNumber*)containerRequired boolValue];
	}else if (containerRequired && [containerRequired isKindOfClass:[NSString class]]) {
		*customContainerOut = (NSString*)containerRequired;
		return YES; //right?
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
			return NO;
		}
	}

	// //app-sandbox: invalid
	// NSNumber *appSandbox = entitlements[@"com.apple.security.app-sandbox"];
	// if (appSandbox && [appSandbox isKindOfClass:[NSNumber class]]) {
	//
	// }

	// apps in containers/Bundle/ always containerized by default
	if([path hasPrefix:@"/var/containers/Bundle/"] || [path hasPrefix:@"/private/var/containers/Bundle/"])
		return YES;

	return NO; //other paths such rootfs/preboot/var don't containerized by default
}

NSString *constructTeamIdentifierForEntitlements(NSDictionary *entitlements) {
	NSString *teamIdentifier = entitlements[@"com.apple.developer.team-identifier"];
	if (teamIdentifier && [teamIdentifier isKindOfClass:[NSString class]]) {
		return teamIdentifier;
	}
	return nil;
}

NSDictionary *constructEnvironmentVariablesForContainerPath(NSString *containerPath, BOOL isContainerized) {
	NSString *homeDir = isContainerized ? containerPath : jbroot(@"/var/mobile");
	NSString *tmpDir = isContainerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : jbroot(@"/var/tmp");
	return @{
		@"CFFIXED_USER_HOME" : homeDir,
		@"HOME" : homeDir,
		@"TMPDIR" : tmpDir
	};
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

void registerPath(NSString *path, BOOL forceSystem)
{
	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];

	path = path.stringByResolvingSymlinksInPath.stringByStandardizingPath;

	NSDictionary *appInfoPlist = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
	NSString *appBundleID = [appInfoPlist objectForKey:@"CFBundleIdentifier"];

	if(!appBundleID) {
		fprintf(stderr, _("Error: Unable to parse app %s\n"), path.fileSystemRepresentation);
		return;
	}

	BOOL isRemovableSystemApp = [[NSFileManager defaultManager] fileExistsAtPath:[@"/System/Library/AppSignatures" stringByAppendingPathComponent:appBundleID]];
	BOOL registerAsUser = isDefaultInstallationPath(path) && !isRemovableSystemApp && !forceSystem;

	NSMutableDictionary *dictToRegister = [NSMutableDictionary dictionary];

	// Add entitlements

	NSString *appExecutablePath = [path stringByAppendingPathComponent:appInfoPlist[@"CFBundleExecutable"]];
	NSDictionary *entitlements = dumpEntitlementsFromBinaryAtPath(appExecutablePath);
	if (entitlements) {
		dictToRegister[@"Entitlements"] = entitlements;
	}

	// Misc

	dictToRegister[@"ApplicationType"] = registerAsUser ? @"User" : @"System";
	dictToRegister[@"CFBundleIdentifier"] = appBundleID;
	dictToRegister[@"CodeInfoIdentifier"] = appBundleID;
	dictToRegister[@"CompatibilityState"] = @0;

 	NSString* appDataContainerID = nil;
	BOOL appContainerized = constructContainerizationForEntitlements(path, entitlements, &appDataContainerID);
	dictToRegister[@"IsContainerized"] = @(appContainerized);
	if (appContainerized) {
		MCMContainer *appContainer = [NSClassFromString(@"MCMAppDataContainer") containerWithIdentifier:appBundleID createIfNecessary:YES existed:nil error:nil];
		NSString *containerPath = [appContainer url].path;

		dictToRegister[@"Container"] = containerPath; /*
		if app executable using another container in entitlements, 
		lsd still create the app-bundle-id container for EnvironmentVariables but set Container-Path to  /var/mobile,  
		when executable  actually runs, the kernel sandbox framework will ask the containerermanagerd to get the container defined in entitlements */
		dictToRegister[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(containerPath, YES);
	} else {
		dictToRegister[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(nil, NO);
	}

	dictToRegister[@"IsDeletable"] = @(registerAsUser || isRemovableSystemApp);
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

		NSMutableDictionary *pluginDict = [NSMutableDictionary dictionary];

		// Add entitlements

		NSString *pluginExecutablePath = [pluginPath stringByAppendingPathComponent:pluginInfoPlist[@"CFBundleExecutable"]];
		NSDictionary *pluginEntitlements = dumpEntitlementsFromBinaryAtPath(pluginExecutablePath);
		if (pluginEntitlements) {
			pluginDict[@"Entitlements"] = pluginEntitlements;
		}

		// Misc

		pluginDict[@"ApplicationType"] = @"PluginKitPlugin";
		pluginDict[@"CFBundleIdentifier"] = pluginBundleID;
		pluginDict[@"CodeInfoIdentifier"] = pluginBundleID;
		pluginDict[@"CompatibilityState"] = @0;

		NSString* pluginDataContainerID = nil;
		BOOL pluginContainerized = constructContainerizationForEntitlements(pluginPath, pluginEntitlements, &pluginDataContainerID);
		pluginDict[@"IsContainerized"] = @(pluginContainerized);
		if (pluginContainerized) {
			/* a plugin may use app's container, but lsd still create plugin-bundle-id container for it */
			MCMContainer *pluginContainer = [NSClassFromString(@"MCMPluginKitPluginDataContainer") containerWithIdentifier:pluginBundleID createIfNecessary:YES existed:nil error:nil];
			NSString *pluginContainerPath = [pluginContainer url].path;

			pluginDict[@"Container"] = pluginContainerPath;
			pluginDict[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(pluginContainerPath, pluginContainerized);
		} else {
			pluginDict[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(nil, pluginContainerized);
		}

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

	if (![workspace registerApplicationDictionary:dictToRegister]) {
		fprintf(stderr, _("Error: Unable to register %s\n"), path.fileSystemRepresentation);
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

	return;

	// char jbrootpath[PATH_MAX];
	// assert(realpath(jbroot("/"), jbrootpath) != NULL);

	// //if arg is a path, it should be a jbroot-based path and starts with /
	// NSString* path = [NSString stringWithFormat:@"%s%@", jbrootpath, arg];

	// bool usingPath = [arg containsString:@"/"];
	// if(usingPath) {
	// 	NSString* path = jbroot(arg);
	// 	targetApp = [LSApplicationProxy applicationProxyForIdentifier:path];
	// }

	// LSApplicationProxy* targetApp = nil;
	// LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
	// for (LSApplicationProxy *app in [workspace allApplications]) {
	// 	//app.bundleURL is always *real-path*
	// 	if( [app.bundleURL.path isEqualToString:path] || [app.bundleIdentifier isEqualToString:arg] )
	// 	{
	// 		targetApp = app;
	// 		break;
	// 	}
	// }

	// if(!targetApp) {
	// 	fprintf(stderr, _("Error: Unable to find app %s\n"), arg.UTF8String);
	// 	return;
	// }

	/* clean up the app's data containers, 
	including group data containers and plug-in data containers, 
	but don't use container-path directly, it may be /var/mobile */

	// MCMContainer *appContainer = [NSClassFromString(@"MCMAppDataContainer") containerWithIdentifier:targetApp.bundleIdentifier createIfNecessary:NO existed:YES? error:nil];
	// if(appContainer) {
	// 	NSError *error;
	// 	destroyContainerWithCompletion  //[NSFileManager.defaultManager removeItemAtPath:appContainer.url.path  error:nil];
	// }

	// // delete group container paths
	// [[targetApp groupContainerURLs] enumerateKeysAndObjectsUsingBlock:^(NSString* groupId, NSURL* groupURL, BOOL* stop)
	// {
	// 	// If another app still has this group, don't delete it
	// 	NSArray<LSApplicationProxy*>* appsWithGroup = applicationsWithGroupId(groupId);
	// 	if(appsWithGroup.count > 1)
	// 	{
	// 		NSLog(@"[uninstallApp] not deleting %@, appsWithGroup.count:%lu", groupURL, appsWithGroup.count);
	// 		return;
	// 	}

	// 	NSLog(@"[uninstallApp] deleting %@", groupURL);
	// 	[[NSFileManager defaultManager] removeItemAtURL:groupURL error:nil];
	// }];

	// // delete app plugin paths
	// for(LSPlugInKitProxy* pluginProxy in targetApp.plugInKitPlugins)
	// {
	// 	NSURL* pluginURL = pluginProxy.dataContainerURL;
	// 	if(pluginURL)?????container????
	// 	{
	// 		NSLog(@"[uninstallApp] deleting %@", pluginURL);
	// 		destroyContainerWithCompletion  //[[NSFileManager defaultManager] removeItemAtURL:pluginURL error:nil];
	// 	}
	// }

	// //there is a bug in unregisterApplication:, if path does exists but its realpath changed, it fault.
	// if (![workspace unregisterApplication:targetApp.bundleURL]) {
	// 	fprintf(stderr, _("Error: Unable to unregister %s : %s\n"), targetApp.bundleIdentifier.UTF8String, targetApp.bundleURL.path.UTF8String);
	// }
}

void listBundleID(void) {
	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
	for (LSApplicationProxy *app in [workspace allApplications]) {
		printf("%s : %s\n", [[app bundleIdentifier] UTF8String], [[app bundleURL] fileSystemRepresentation]);
	}
}

void printfNSObject(id obj)
{
	unsigned int outCount=0;
    objc_property_t *properties =class_copyPropertyList([obj class], &outCount);
    for (int i = 0; i<outCount; i++)
    {
        objc_property_t property = properties[i];
        const char* char_f =property_getName(property);
        NSString *propertyName = [NSString stringWithUTF8String:char_f];
		@try{
        id propertyValue = [obj valueForKey:(NSString *)propertyName];
		printf("%s:\t%s\n", propertyName.UTF8String, [propertyValue debugDescription].UTF8String);
		}
        @catch (NSException *exception)
        {
			printf("***unaccessible %s\n", propertyName.UTF8String);
		}
    }
    free(properties);
}

void infoForBundleID(NSString *bundleID) {
	LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
	// printfNSObject(app.correspondingApplicationRecord);

	if ([[app appState] isValid]) {
		printf(_("Name: %s\n"), [[app localizedNameForContext:nil] UTF8String]);
		printf(_("Bundle Identifier: %s\n"), [[app bundleIdentifier] UTF8String]);
		printf(_("Executable Name: %s\n"), [[app bundleExecutable] UTF8String]);
		printf(_("Path: %s\n"), [[app bundleURL] fileSystemRepresentation]);
		printf(_("Container Path: %s\n"), [[app containerURL] fileSystemRepresentation]);
		printf(_("Vendor Name: %s\n"), [[app vendorName] UTF8String]);
		printf(_("Team ID: %s\n"), [[app teamID] UTF8String]);
		printf(_("Type: %s\n"), [[app applicationType] UTF8String]);
		printf(_("Removable: %s\n"), [app isDeletable] ? _("true") : _("false"));

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
			registerPath(bundlePath, NO);
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
			{NULL, 0, NULL, 0}};

		int index = 0, code = 0;

		while ((code = getopt_long(argc, argv, "ap:u:rl::si:hfv", longOptions, &index)) != -1) {
			switch (code) {
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
