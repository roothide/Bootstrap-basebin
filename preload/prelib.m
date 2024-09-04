#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syslimits.h>
#include <mach-o/dyld.h>
#include <Foundation/Foundation.h>

#include "sandbox.h"

extern char*const* environ;

void unsandbox(const char* sbtoken) {
	char extensionsCopy[strlen(sbtoken)];
	strcpy(extensionsCopy, sbtoken);
	char *extensionToken = strtok(extensionsCopy, "|");
	while (extensionToken != NULL) {
		sandbox_extension_consume(extensionToken);
		extensionToken = strtok(NULL, "|");
	}
}

bool checkpatchedexe() {
	char executablePath[PATH_MAX]={0};
	uint32_t bufsize=sizeof(executablePath);
	assert(_NSGetExecutablePath(executablePath, &bufsize) == 0);
	
	char patcher[PATH_MAX];
	snprintf(patcher, sizeof(patcher), "%s.roothidepatch", executablePath);
	if(access(patcher, F_OK)==0) 
		return false;

	return true;
}

static void __attribute__((__constructor__)) preload()
{
	if(getppid() != 1) return;

    NSString* rebuildFile = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@".rebuild"];
	NSDictionary* rebuildStatus = [NSDictionary dictionaryWithContentsOfFile:rebuildFile];

	const char* sbtoken = [rebuildStatus[@"sb_token"] UTF8String];
	if(sbtoken) {
		unsandbox(sbtoken);
	}

	int found=0;
	int count=_dyld_image_count();
    for(int i=0; i<count; i++) {
		const char* path = _dyld_get_image_name(i);
		NSLog(@"dyldlib=%s", path);
		if(strstr(path, "/basebin/bootstrap.dylib")) {
			found = 1;
			break;
		}
    }
    
	if(!found) 
	{
		if(!dlopen("@executable_path/.jbroot/basebin/bootstrap.dylib", RTLD_NOW)) {
			assert(checkpatchedexe());
		}
	}

    return;
}
