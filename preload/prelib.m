#include <stdlib.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <mach-o/dyld.h>
#include <Foundation/Foundation.h>

#include <sandbox.h>
#include "commlib.h"

extern struct mach_header_64* _dyld_get_prog_image_header();

bool check_executable_encrypted()
{
	struct mach_header_64* mh = _dyld_get_prog_image_header();
	if(!mh) return false;

	struct load_command* cmd = (struct load_command*)((uintptr_t)mh + sizeof(struct mach_header_64));
	for(uint32_t i=0; i<mh->ncmds; i++) {
		if(cmd->cmd == LC_ENCRYPTION_INFO_64) {
			struct encryption_info_command_64* encCmd = (struct encryption_info_command_64*)cmd;
			if(encCmd->cryptid != 0) {
				return true;
			} else {
				return false;
			}
		}
		cmd = (struct load_command*)((uintptr_t)cmd + cmd->cmdsize);
	}
	return false;
}

NSDictionary* g_rebuildStatus = nil;

uint64_t jbrand()
{
	NSNumber* jbrand = g_rebuildStatus[@"jbrand"];
	return jbrand.unsignedLongLongValue;
}

const char* jbroot(const char* path)
{
	NSString* jbrootPath = g_rebuildStatus[@"jbroot"];
	NSString* newpath = [jbrootPath stringByAppendingPathComponent:@(path)];
    @synchronized(@"jbroot_cache_lock")
    {
        static NSMutableSet* cache = nil;
        if(!cache) cache = [NSMutableSet new];
        
        [cache addObject:newpath];
        newpath = [cache member:newpath];
    }
    return newpath.fileSystemRepresentation;
}

NSString* __attribute__((overloadable)) jbroot(NSString* path)
{
	NSString* jbrootPath = g_rebuildStatus[@"jbroot"];
	NSString* newPath = [jbrootPath stringByAppendingPathComponent:path];
	return newPath;
}

static void __attribute__((__constructor__)) preload()
{
	// debugserver spawn reparent
	// if(getppid() != 1) return;
	if(get_real_ppid() != 1) return;

    NSString* rebuildFile = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@".rebuild"];
	NSDictionary* rebuildStatus = [NSDictionary dictionaryWithContentsOfFile:rebuildFile];
	NSLog(@"rebuildStatus=%@", rebuildStatus);

	g_rebuildStatus = rebuildStatus;

	const char* sbtoken = [rebuildStatus[@"sb_token"] UTF8String];
	if(sbtoken) {
		unsandbox(sbtoken);
	}

	int found=0;
	int count=_dyld_image_count();
    for(int i=0; i<count; i++) {
		const char* path = _dyld_get_image_name(i);
		// NSLog(@"dyldlib=%s", path);
		if(strstr(path, "/basebin/bootstrap.dylib")) {
			found = 1;
			break;
		}
    }
    
	if(!found) 
	{
		if(check_executable_encrypted())
		{
			ASSERT(requireJIT()==0);

			void init_bypassDyldLibValidation();
			init_bypassDyldLibValidation();
		}
		
		if(!dlopen("@executable_path/.jbroot/basebin/bootstrap.dylib", RTLD_NOW)) {
			NSLog(@"dlopen failed: %s", dlerror());

			char executablePath[PATH_MAX]={0};
			uint32_t bufsize=sizeof(executablePath);
			assert(_NSGetExecutablePath(executablePath, &bufsize) == 0);
			ASSERT(checkpatchedexe(executablePath));
		}
	}

    return;
}
