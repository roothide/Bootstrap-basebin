#import <Foundation/Foundation.h>
#import <Foundation/NSURL.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <dlfcn.h>
#import <getopt.h>
#import <stdio.h>
#include <spawn.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <roothide.h>

#include "../bootstrapd/libbsd.h"

#define APP_PATH	@"/Applications"

#define SYSLOG(...)

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
- (NSURL *)dataContainerURL;
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

			NSNumber*AppDataContainers = entitlements[@"com.apple.private.security.storage.AppDataContainers"];
			if (AppDataContainers && [AppDataContainers isKindOfClass:[NSNumber class]]) {
				if (AppDataContainers.boolValue) return YES; //hack way
			}

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
	NSString *homeDir = isContainerized ? containerPath : @"/var/mobile";
	NSString *tmpDir = isContainerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : @"/var/tmp";
	return @{
		@"CFFIXED_USER_HOME" : homeDir,
		@"HOME" : homeDir,
		@"TMPDIR" : tmpDir
	}.mutableCopy;
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
];


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


void freeplay(NSString* bundlePath)
{
    NSFileManager* fm = NSFileManager.defaultManager;

    if(![fm fileExistsAtPath:[bundlePath stringByAppendingPathExtension:@"appbackup"]])
        return;

    if(![fm fileExistsAtPath:[bundlePath stringByAppendingPathComponent:@"SC_Info"]])
        return;

    assert([fm moveItemAtPath:bundlePath toPath:[bundlePath stringByAppendingPathExtension:@"tmp"] error:nil]);
    assert([fm moveItemAtPath:[bundlePath stringByAppendingPathExtension:@"appbackup"] toPath:bundlePath error:nil]);

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

			if ([infoDict[@"CFBundlePackageType"] isEqualToString:@"FMWK"]) continue;
            
			if (![infoDict[@"CFBundlePackageType"] isEqualToString:@"APPL"]) continue;

			NSString *bundleId = infoDict[@"CFBundleIdentifier"];
			NSString *bundleExecutable = infoDict[@"CFBundleExecutable"];
			if (!bundleId || !bundleExecutable) continue;

			NSString *bundleMainExecutablePath = [[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:bundleExecutable];
			if (![fm fileExistsAtPath:bundleMainExecutablePath]) continue;

            posix_spawnattr_t attr;
            posix_spawnattr_init(&attr);
            posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);

            pid_t pid=0;
            char* args[] = {(char*)bundleMainExecutablePath.UTF8String,(char*)bundleMainExecutablePath.UTF8String,NULL};
            int ret = posix_spawn(&pid, args[0], NULL, &attr, args, NULL);
            NSLog(@"freeplay: %d,%s : %d : %@", ret, strerror(ret), pid, bundleMainExecutablePath);
            if(ret==0 && pid) {
                kill(pid, SIGKILL);
            }
        }
    }

    assert([fm moveItemAtPath:bundlePath toPath:[bundlePath stringByAppendingPathExtension:@"appbackup"] error:nil]);
    assert([fm moveItemAtPath:[bundlePath stringByAppendingPathExtension:@"tmp"] toPath:bundlePath error:nil]);
}




// #define BOOTSTRAP_INSTALL_NAME	"@loader_path/.jbroot/basebin/bootstrap.dylib"
#define BOOTSTRAP_INSTALL_NAME	"@loader_path/.prelib"

int patch_macho(struct mach_header_64* header)
{
    int first_sec_off = 0;
    
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
                
        switch(lc->cmd) {
                
            case LC_LOAD_DYLIB:
			{
                struct dylib_command* idcmd = (struct dylib_command*)lc;
                char* name = (char*)((uint64_t)idcmd + idcmd->dylib.name.offset);
                
                if(strcmp(name, BOOTSTRAP_INSTALL_NAME)==0) {
                    SYSLOG("bootstrap library exists!\n");
					return 0;
                }
                break;
            }
                
            case LC_SEGMENT_64: {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                
                SYSLOG("segment: %s file=%llx:%llx vm=%16llx:%16llx\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
                
                struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
                for(int j=0; j<seg->nsects; j++)
                {
                    SYSLOG("section[%d] = %s/%s offset=%x vm=%16llx:%16llx\n", j, sec[j].segname, sec[j].sectname,
                          sec[j].offset, sec[j].addr, sec[j].size);
                    
                    if(sec[j].offset && (first_sec_off==0 || first_sec_off>sec[j].offset)) {
                        SYSLOG("first_sec_off %x => %x\n", first_sec_off, sec[j].offset);
                        first_sec_off = sec[j].offset;
                    }
                }
                break;
            }
		}
        
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
	}

	int addsize = sizeof(struct dylib_command) + strlen(BOOTSTRAP_INSTALL_NAME) + 1;
	if(addsize%sizeof(void*)) addsize = (addsize/sizeof(void*) + 1) * sizeof(void*); //align
	if(first_sec_off < (sizeof(*header)+header->sizeofcmds+addsize))
	{
		fprintf(stderr, "mach-o header has no enough space!\n");
		return -1;
	}
	
	struct dylib_command* newlib = (struct dylib_command*)((uint64_t)header + sizeof(*header) + header->sizeofcmds);

	//memmove((void*)((uint64_t)newlib + addsize), newlib, header->sizeofcmds);

	newlib->cmd = LC_LOAD_DYLIB;
	newlib->cmdsize = addsize;
	newlib->dylib.timestamp = 0;
	newlib->dylib.current_version = 0;
	newlib->dylib.compatibility_version = 0;
	newlib->dylib.name.offset = sizeof(*newlib);
	strcpy((char*)newlib+sizeof(*newlib), BOOTSTRAP_INSTALL_NAME);
	
	header->sizeofcmds += addsize;
	header->ncmds++;

	return 0;
}

int patch_executable(const char* file, uint32_t offset)
{
	int fd = open(file, O_RDWR);
    if(fd < 0) {
        fprintf(stderr, "open %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }
    
    struct stat st;
    if(stat(file, &st) < 0) {
        fprintf(stderr, "stat %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }
    
    SYSLOG("file size = %lld\n", st.st_size);
    
    void* macho = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if(macho == MAP_FAILED) {
        fprintf(stderr, "map %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }

    struct mach_header_64* header = (struct mach_header_64*)((uint64_t)macho + offset);

	int retval = patch_macho(header);
	SYSLOG("patch macho @ %x : %d", offset, retval);

	if(write(fd, macho, st.st_size) != st.st_size) {
		fprintf(stderr, "write %lld error:%d,%s\n", st.st_size, errno, strerror(errno));
	}

    munmap(macho, st.st_size);

    close(fd);

    return retval;
}



void machoEnumerateArchs(FILE* machoFile, void (^archEnumBlock)(struct mach_header_64* header, uint32_t offset, bool* stop))
{
	struct mach_header_64 mh={0};
	if(fseek(machoFile,0,SEEK_SET)!=0)return;
	if(fread(&mh,sizeof(mh),1,machoFile)!=1)return;
	
	if(mh.magic==FAT_MAGIC || mh.magic==FAT_CIGAM)//and || mh.magic==FAT_MAGIC_64 || mh.magic==FAT_CIGAM_64? with fat_arch_64
	{
		struct fat_header fh={0};
		if(fseek(machoFile,0,SEEK_SET)!=0)return;
		if(fread(&fh,sizeof(fh),1,machoFile)!=1)return;
		
		for(int i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++)
		{
			uint32_t archMetadataOffset = sizeof(fh) + sizeof(struct fat_arch) * i;

			struct fat_arch fatArch={0};
			if(fseek(machoFile, archMetadataOffset, SEEK_SET)!=0)break;
			if(fread(&fatArch, sizeof(fatArch), 1, machoFile)!=1)break;

			if(fseek(machoFile, OSSwapBigToHostInt32(fatArch.offset), SEEK_SET)!=0)break;
			if(fread(&mh, sizeof(mh), 1, machoFile)!=1)break;

			if(mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) continue; //require Macho64
			
			bool stop = false;
			archEnumBlock(&mh, OSSwapBigToHostInt32(fatArch.offset), &stop);
			if(stop) break;
		}
	}
	else if(mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64) //require Macho64
	{
		bool stop=false;
		archEnumBlock(&mh, 0, &stop);
	}
}

void machoGetInfo(FILE* candidateFile, bool *isMachoOut, bool *isLibraryOut)
{
	if (!candidateFile) return;

	__block bool isMacho=false;
	__block bool isLibrary = false;
	
	machoEnumerateArchs(candidateFile, ^(struct mach_header_64* header, uint32_t offset, bool* stop) {
		isMacho = true;
		isLibrary = OSSwapLittleToHostInt32(header->filetype) != MH_EXECUTE;
		*stop = true;
	});

	if (isMachoOut) *isMachoOut = isMacho;
	if (isLibraryOut) *isLibraryOut = isLibrary;
}

int patch_app_exe(const char* file)
{
	FILE* fp = fopen(file, "rb");
	if(!fp) return -1;
	machoEnumerateArchs(fp, ^(struct mach_header_64* header, uint32_t offset, bool* stop) {
		patch_executable(file, offset);
	});
	fclose(fp);
	return 0;
}


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


	//NSLog(@"Info=%@", appInfoPlist);
    NSMutableArray* urltypes = [appInfoPlist[@"CFBundleURLTypes"] mutableCopy];
    for(int i=0; i<urltypes.count; i++) {
       //NSLog(@"schemes=%@", urltypes[i][@"CFBundleURLSchemes"]);
        
        NSMutableArray* schemes = [urltypes[i][@"CFBundleURLSchemes"] mutableCopy];
        [schemes removeObjectsInArray:blockedURLSchemes];
        //NSLog(@"new schemes=%@", schemes);

        urltypes[i][@"CFBundleURLSchemes"] = schemes.copy;
    }
    appInfoPlist[@"CFBundleURLTypes"] = urltypes.copy;


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
        if(!isAppleBundle && ![NSFileManager.defaultManager fileExistsAtPath:[path stringByAppendingString:@"/../_TrollStore"]])
        {
            freeplay(path);
        }

        if(![NSFileManager.defaultManager fileExistsAtPath:rebuildFile])
        {
            //NSLog(@"patch macho: %@", [path stringByAppendingPathComponent:executableName]);
            int patch_app_exe(const char* file);
            patch_app_exe([path stringByAppendingPathComponent:executableName].UTF8String);

             char* argv[] = {"/basebin/rebuildapp", (char*)rootfs(path).UTF8String, NULL};
            assert(execBinary(jbroot(argv[0]), argv) == 0);
            
            [[NSString new] writeToFile:rebuildFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
       }

        // NSString* newExecutableName = @".preload";
        // appInfoPlist[@"CFBundleExecutable"] = newExecutableName;

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

	if(jbrootexists) 
    {
        dictToRegister[@"EnvironmentVariables"][@"_JBROOT"] = jbroot(@"/");
        dictToRegister[@"EnvironmentVariables"][@"_SBTOKEN"] = @(sbtoken);
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

		if([blockedAppPlugins containsObject:pluginBundleID]) continue;

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

		if(jbrootexists) 
		{
			pluginDict[@"EnvironmentVariables"][@"_JBROOT"] = jbroot(@"/");
			pluginDict[@"EnvironmentVariables"][@"_SBTOKEN"] = @(sbtoken);
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
	//printfNSObject(app);

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
