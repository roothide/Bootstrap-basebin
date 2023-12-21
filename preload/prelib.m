#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syslimits.h>
#include <mach-o/dyld.h>
#include <Foundation/Foundation.h>

#include "sandbox.h"

#define JB_ROOT_PATH(path) ({ \
	char *outPath = alloca(PATH_MAX); \
	strlcpy(outPath, getenv("_JBROOT"), PATH_MAX); \
	strlcat(outPath, path, PATH_MAX); \
	(outPath); \
})


void unsandbox(char* sbtoken) {
	char extensionsCopy[strlen(sbtoken)];
	strcpy(extensionsCopy, sbtoken);
	char *extensionToken = strtok(extensionsCopy, "|");
	while (extensionToken != NULL) {
		sandbox_extension_consume(extensionToken);
		extensionToken = strtok(NULL, "|");
	}
}

static void __attribute__((__constructor__)) preload()
{
	if(getppid() != 1) return;

	char* sbtoken = getenv("_SBTOKEN");
	if(sbtoken) {
		unsandbox(sbtoken);
		unsetenv("_SBTOKEN");
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
    
	if(!found) dlopen(JB_ROOT_PATH("/basebin/bootstrap.dylib"), RTLD_NOW);

	unsetenv("_JBROOT");

    return;
}
