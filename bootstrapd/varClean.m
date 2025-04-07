
#include <Foundation/Foundation.h>
#include <roothide.h>

char* varCleanPatterns[][4] = {
	{"","Library/Preferences",".plist",(char*)true},
	{"","Library/SplashBoard/Snapshots","",(char*)true},
	{"","Library/Saved Application State",".savedState",(char*)true},
	
	{"","Library/Caches","",(char*)false},
	{"","Library/WebKit","",(char*)false},
	{"","Library/Cookies",".binarycookies",(char*)false},
	{"","Library/HTTPStorages","",(char*)false},
	{"","Library/Application Support/Containers","",(char*)false},
};

dispatch_queue_t varCleanQueue = nil;
NSMutableDictionary* varCleanDict = nil;

void doVarClean(const char* bundleIdentifier, bool all)
{
	//if the user has enabled URLSchemes, this means the user does not need to hide the "jailbreak"
	if(access(jbroot("/var/mobile/.allow_url_schemes"), F_OK)==0) {
		return;
	}

	NSLog(@"varClean: doVarClean(%d) %s", all, bundleIdentifier);

	for(int i=0; i<sizeof(varCleanPatterns)/sizeof(varCleanPatterns[0]); i++) {
		char** pattern = varCleanPatterns[i];
		bool force = (bool)pattern[3];
		if(!all && !force) continue;

		char path[PATH_MAX];
		snprintf(path,sizeof(path),"/var/mobile/%s/%s%s%s", pattern[1], bundleIdentifier, pattern[0], pattern[2]);
		if(access(path, F_OK)==0) {
			BOOL ret = [NSFileManager.defaultManager removeItemAtPath:@(path) error:nil];
			NSLog(@"varClean: remove app file %s : %d\n", path, ret);
		}
	}
}

void varCleanInit()
{
	for(int i=0; i<sizeof(varCleanPatterns)/sizeof(varCleanPatterns[0]); i++) {
		char** pattern = varCleanPatterns[i];
		bool force = (bool)pattern[3];
		if(!force) continue;

		char path[PATH_MAX];
		snprintf(path,sizeof(path),"/var/mobile/%s", pattern[1]);

		int fd = open(path, O_EVTONLY);
		if (fd < 0) {
			NSLog(@"cannot open dir: %s", path);
			continue;
		}

		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd,
														DISPATCH_VNODE_WRITE | DISPATCH_VNODE_DELETE | DISPATCH_VNODE_EXTEND |
														DISPATCH_VNODE_ATTRIB | DISPATCH_VNODE_LINK | DISPATCH_VNODE_RENAME |
														DISPATCH_VNODE_REVOKE, varCleanQueue);

    	if (!source) {
			close(fd);
			NSLog(@"cannot create DispatchSource");
			continue;
		}

		dispatch_source_set_event_handler(source, ^{
			unsigned long eventTypes = dispatch_source_get_data(source);
			if (eventTypes & DISPATCH_VNODE_WRITE) {
				//delay for avoiding springboard lag
				dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), varCleanQueue, ^{
					for(NSString* bundleIdentifier in varCleanDict) {
						doVarClean(bundleIdentifier.UTF8String, false);
					}
				});
			}
		});

		dispatch_resume(source);
	}
}

int varClean(NSString* bundleIdentifier)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		varCleanQueue = dispatch_queue_create("varClean", DISPATCH_QUEUE_CONCURRENT);
		varCleanDict = [NSMutableDictionary new];
		varCleanInit();
	});

	dispatch_async(varCleanQueue, ^{
		varCleanDict[bundleIdentifier] = @(true);
		doVarClean(bundleIdentifier.UTF8String, true);
	});

	return 0;
}

