#include <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <roothide.h>

#include "../bootstrapd/libbsd.h"

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {

		NSLog(@"preload @ %s", argv[0]);

		NSString* appInfoPath = [NSString stringWithFormat:@"%s/Info.plist", dirname(argv[0])];
		NSDictionary *appInfoPlist = [NSDictionary dictionaryWithContentsOfFile:appInfoPath];
		NSString* executableName = appInfoPlist[@"CFBundleExecutable"];
		NSLog(@"executableName=%@", executableName);

		if(getppid()==1) 
		{
			const char* sbtoken = bsd_getsbtoken();
			if(sbtoken) {
				setenv("_SBTOKEN", sbtoken, 1);
			} else {
				char patcher[PATH_MAX];
				snprintf(patcher, sizeof(patcher), "%s/%s.roothidepatch", dirname(argv[0]), executableName.UTF8String);
				if(access(patcher, F_OK)==0) 
					abort();
			}

			setenv("DYLD_INSERT_LIBRARIES", "@executable_path/.jbroot/basebin/bootstrap.dylib:@executable_path/.prelib", 1);
			setenv("_JBROOT", jbroot("/"), 1);
		}

		char executable[PATH_MAX];
		snprintf(executable, sizeof(executable), "%s/%s", dirname(argv[0]), executableName.UTF8String);

		argv[0] = executable;
		execv(argv[0], argv); //don't use envp
		NSLog(@"exec failed %s for %s", strerror(errno), argv[0]);
		abort();
	}
}
