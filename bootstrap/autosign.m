#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/syslimits.h>
#include <fcntl.h>
#include <libgen.h>
#include <spawn.h>
#include <errno.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <roothide.h>
#include "common.h"
#include "fishhook.h"

#include <Foundation/Foundation.h>

// #undef SYSLOG
// #define SYSLOG(...)

NSMutableSet* gUpdatedAppBundles = nil;

bool g_sign_failed = false;

extern void _exit(int code);


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

void sign_apps() {
	SYSLOG("app sign %s", gUpdatedAppBundles.description.UTF8String);
	for(NSString* appbundle in gUpdatedAppBundles)
	{
		char* args[] = {"/basebin/uicache", "-p", (char*)jbroot(appbundle.fileSystemRepresentation), "--patchonly", NULL};
		int status = execBinary(jbroot(args[0]), args);
		if(status != 0) {
			fprintf(stderr, "signapp %s failed: %d\n", appbundle.fileSystemRepresentation, status);
			g_sign_failed = true;
		}
	}
	[gUpdatedAppBundles removeAllObjects];
}

/* `postinst` is called before this */
void sign_check(void) {
	SYSLOG("autosign: sign_check!");

	sign_apps();

	if(g_sign_failed) _exit(-1);
}

void ensure_jbroot_symlink(const char* filepath)
{
	// JBLogDebug("ensure_jbroot_symlink: %s", filepath);

	if(access(filepath, F_OK) !=0 )
		return;

	char realfpath[PATH_MAX]={0};
	ASSERT(realpath(filepath, realfpath) != NULL);

	char realdirpath[PATH_MAX+1]={0};
	dirname_r(realfpath, realdirpath);
	if(realdirpath[0] && realdirpath[strlen(realdirpath)-1] != '/') {
		strlcat(realdirpath, "/", sizeof(realdirpath));
	}

	char jbrootpath[PATH_MAX+1]={0};
	ASSERT(realpath(jbroot("/"), jbrootpath) != NULL);
	if(jbrootpath[0] && jbrootpath[strlen(jbrootpath)-1] != '/') {
		strlcat(jbrootpath, "/", sizeof(jbrootpath));
	}

	// JBLogDebug("%s : %s", realdirpath, jbrootpath);

	if(strncmp(realdirpath, jbrootpath, strlen(jbrootpath)) != 0)
		return;

	struct stat jbrootst;
	ASSERT(stat(jbrootpath, &jbrootst) == 0);
	
	char sympath[PATH_MAX];
	snprintf(sympath,sizeof(sympath),"%s/.jbroot", realdirpath);

	struct stat symst;
	if(lstat(sympath, &symst)==0)
	{
		if(S_ISLNK(symst.st_mode))
		{
			if(stat(sympath, &symst) == 0)
			{
				if(symst.st_dev==jbrootst.st_dev 
					&& symst.st_ino==jbrootst.st_ino)
					return;
			}

			ASSERT(unlink(sympath) == 0);
			
		} else {
			//not a symlink? just let it go
			return;
		}
	}

	if(symlink(jbrootpath, sympath) ==0 ) {
		// JBLogError("update .jbroot @ %s\n", sympath);
	} else {
		// JBLogError("symlink error @ %s\n", sympath);
	}
}

void machoEnumerateArchs(FILE* machoFile, bool (^archEnumBlock)(struct mach_header_64* header, uint32_t offset))
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
			
			if(!archEnumBlock(&mh, OSSwapBigToHostInt32(fatArch.offset))) 
				break;
		}
	}
	else if(mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64) //require Macho64
	{
		archEnumBlock(&mh, 0);
	}
}

void machoGetInfo(FILE* candidateFile, bool *isMachoOut, bool *isLibraryOut)
{
	if (!candidateFile) return;

	__block bool isMacho=false;
	__block bool isLibrary = false;
	
	machoEnumerateArchs(candidateFile, ^bool(struct mach_header_64* header, uint32_t offset) {
		switch(OSSwapLittleToHostInt32(header->filetype)) {
			case MH_DYLIB:
			case MH_BUNDLE:
				isLibrary = true;
			case MH_EXECUTE:
				isMacho = true;
				return false;

			default:
				return true;
		}
	});

	if (isMachoOut) *isMachoOut = isMacho;
	if (isLibraryOut) *isLibraryOut = isLibrary;
}

int autosign(char* path)
{
	if(strstr(path, "/var/mobile/Library/pkgmirror/"))
		return 0;

	const char* jbpath = rootfs(path);

	if(stringStartsWith(jbpath, "/usr/lib/frida/frida-agent.dylib")) // xxx.dpkg-new
		return 0;

    FILE* fp = fopen(path, "rb");
    if(fp) {
        bool ismacho=false,islib=false;
        machoGetInfo(fp, &ismacho, &islib);
        
        if(ismacho) 
        {
			SYSLOG("autosign: sign %s\n", jbpath);

            if(!islib)
            {
                char sent[PATH_MAX];
                snprintf(sent,sizeof(sent),"-S%s", jbroot("/basebin/bootstrap.entitlements"));

                char* args[] = {"ldid", "-M", sent, path, NULL};
				int status = execBinary(jbroot("/basebin/ldid"), args);
				if(status != 0) {
					fprintf(stderr, "ldid %s failed: %d\n", jbpath, status);
					g_sign_failed = true;
				}
            }
			else
			{
				//since RootHidePatcher always re-sign with entitlements for all mach-o files....
                char* args[] = {"ldid", "-S", path, NULL};
				int status = execBinary(jbroot("/basebin/ldid"), args);
				if(status != 0) {
					fprintf(stderr, "ldid %s failed: %d\n", jbpath, status);
					g_sign_failed = true;
				}
			}
			
			if(strncmp(jbpath, "/Applications/", sizeof("/Applications/")-1) == 0)
			{
				const char* p1 = strchr(jbpath+sizeof("/Applications/")-1, '/');
				if(p1)
				{
					char appbundle[PATH_MAX]={0};
					snprintf(appbundle, sizeof(appbundle), "%.*s", (int)(p1-jbpath), jbpath);
					[gUpdatedAppBundles addObject:[NSString stringWithUTF8String:appbundle]];
					SYSLOG("autosign: add app bundle %s\n", appbundle);
				}
			} else {
				char* args[] = {"fastPathSign", path, NULL};
				int status = execBinary(jbroot("/basebin/fastPathSign"), args);
				if(status != 0) {
					fprintf(stderr, "sign %s failed: %d\n", jbpath, status);
					g_sign_failed = true;
				}
			}

            ensure_jbroot_symlink(path);
        }

        fclose(fp);
    }

    return 0;
}


int (*dpkghook_orig_close)(int fd);
int dpkghook_new_close(int fd)
{
    int olderr=errno;

    char path[PATH_MAX]={0};
    int s=fcntl(fd, F_GETPATH, path);

    errno = olderr;

    int ret = dpkghook_orig_close(fd);

	 olderr=errno;

    if(s==0 && path[0])
    {
        struct stat st={0};
        stat(path, &st);
                
        SYSLOG("close %s %d:%s : %lld\n", getprogname(), fd, rootfs(path), st.st_size);

        int autosign(char* path);
        autosign(path);
    }

    errno = olderr;
    return ret;
}


int (*dpkghook_orig_rmdir)(char* path);
int dpkghook_new_rmdir(char* path)
{
	SYSLOG("rmdir=%s", path);

    char preload[PATH_MAX];
    snprintf(preload, sizeof(preload), "%s/.preload", path);
	unlink(jbroot(preload));

    char prelib[PATH_MAX];
    snprintf(prelib, sizeof(prelib), "%s/.prelib", path);
	unlink(jbroot(prelib));

    char rebuild[PATH_MAX];
    snprintf(rebuild, sizeof(rebuild), "%s/.rebuild", path);
	unlink(jbroot(rebuild));

    return dpkghook_orig_rmdir(path);
}

int (*dpkghook_orig_system)(const char* command);
int dpkghook_new_system(const char* command)
{
	SYSLOG("system: %s", command);

	// sign_apps();

	return dpkghook_orig_system(command);
}

int (*dpkghook_orig_execvp)(const char *name, char * const *argv);
int dpkghook_new_execvp(const char *name, char * const *argv)
{
	SYSLOG("execvp %s %s\n", name, argv[0]);

	/*
	/Library/dpkg/info/<package>.{prerm,postinst,postrm}
	*/
	const char* path = jbroot(name);
	FILE* fp = fopen(path, "rb");
    if(fp) {
        bool ismacho=false,islib=false;
        machoGetInfo(fp, &ismacho, &islib);
        
        if(ismacho)
        {
            ensure_jbroot_symlink(path);
        }

        fclose(fp);
	}

	// sign_apps();

	return dpkghook_orig_execvp(name, argv);
}

int (*dpkghook_orig_execlp)(const char *name, const char *arg, ...);
int dpkghook_new_execlp(const char *name, const char *arg, ...)
{
	SYSLOG("execlp %s %s\n", name, arg);

	va_list ap;
	const char **argv;
	int n;

	va_start(ap, arg);
	n = 1;
	while (va_arg(ap, char *) != NULL)
		n++;
	va_end(ap);
	argv = alloca((n + 1) * sizeof(*argv));
	if (argv == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	va_start(ap, arg);
	n = 1;
	argv[0] = arg;
	while ((argv[n] = va_arg(ap, char *)) != NULL)
		n++;
	va_end(ap);

	// sign_apps();

	return dpkghook_orig_execvp(name, __DECONST(char **, argv));
}

pid_t (*dpkghook_orig_fork)();
pid_t dpkghook_new_fork() {

	sign_apps();

	return dpkghook_orig_fork();
}

void init_dpkg_hook()
{
	gUpdatedAppBundles = [NSMutableSet new];

	struct rebinding rebindings[] = {
		{"close", dpkghook_new_close, (void**)&dpkghook_orig_close},
		{"rmdir", dpkghook_new_rmdir, (void**)&dpkghook_orig_rmdir},
		{"ie_system", dpkghook_new_system, (void**)&dpkghook_orig_system},
		{"ie_execlp", dpkghook_new_execlp, (void**)&dpkghook_orig_execlp},
		{"ie_execvp", dpkghook_new_execvp, (void**)&dpkghook_orig_execvp},
		{"fork", dpkghook_new_fork, (void**)&dpkghook_orig_fork},
	};
	struct mach_header_64* header = _dyld_get_prog_image_header();
	rebind_symbols_image((void*)header, _dyld_get_image_slide(header), rebindings, sizeof(rebindings)/sizeof(rebindings[0]));

	atexit(sign_check);
}