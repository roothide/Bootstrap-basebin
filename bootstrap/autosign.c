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
#include <assert.h>
#include <spawn.h>
#include <errno.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <roothide.h>
#include "common.h"
#include "fishhook.h"

void ensure_jbroot_symlink(const char* dirpath)
{
	//JBLogDebug("ensure_jbroot_symlink: %s", dirpath);

	if(access(dirpath, F_OK) !=0 )
		return;

	char realdirpath[PATH_MAX];
	assert(realpath(dirpath, realdirpath) != NULL);
	if(realdirpath[strlen(realdirpath)] != '/') strcat(realdirpath, "/");

	char jbrootpath[PATH_MAX];
	char jbrootpath2[PATH_MAX];
	snprintf(jbrootpath, sizeof(jbrootpath), "/private/var/containers/Bundle/Application/.jbroot-%016llX/", jbrand());
	snprintf(jbrootpath2, sizeof(jbrootpath2), "/private/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX/", jbrand());

	if(strncmp(realdirpath, jbrootpath, strlen(jbrootpath)) != 0
		&& strncmp(realdirpath, jbrootpath2, strlen(jbrootpath2)) != 0 
		&& strncmp(realdirpath, "/private/var/db/", sizeof("/private/var/db/")-1) !=0
		)
		return;

	struct stat jbrootst;
	assert(stat(jbrootpath, &jbrootst) == 0);
	
	char sympath[PATH_MAX];
	snprintf(sympath,sizeof(sympath),"%s/.jbroot", dirpath);

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

			assert(unlink(sympath) == 0);
			
		} else {
			//not a symlink? just let it go
			return;
		}
	}

	if(symlink(jbrootpath, sympath) ==0 ) {
		//JBLogError("update .jbroot @ %s\n", sympath);
	} else {
		//JBLogError("symlink error @ %s\n", sympath);
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

int autosign(char* path)
{
    FILE* fp = fopen(path, "rb");
    if(fp) {
        bool ismacho=false,islib=false;
        machoGetInfo(fp, &ismacho, &islib);
        
        if(ismacho) 
        {
			printf("sign %s\n", rootfs(path));

            if(!islib)
            {
				// if(strstr(path, "/Applications/"))
				// {
				// 	machoEnumerateArchs(fp, ^(struct fat_arch* arch, uint32_t archMetadataOffset, uint32_t archOffset, bool* stop) {
				// 		patch_executable(path, archOffset);
				// 	});
				// }

                char sent[PATH_MAX];
                snprintf(sent,sizeof(sent),"-S%s", jbroot("/basebin/bootstrap.entitlements"));

                char* args[] = {"ldid", "-M", sent, path, NULL};
				assert(execBinary(jbroot("/basebin/ldid"), args) == 0);
            }
			else
			{
				//since RootHidePatcher always re-sign with entitlements for all mach-o files....
                char* args[] = {"ldid", "-S", path, NULL};
				assert(execBinary(jbroot("/basebin/ldid"), args) == 0);
			}

            char* args[] = {"fastPathSign", path, NULL};
			assert(execBinary(jbroot("/basebin/fastPathSign"), args) == 0);

            char dpath[PATH_MAX];
            ensure_jbroot_symlink(dirname_r(path,dpath));
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

void init_dpkg_hook()
{
	struct rebinding rebindings[] = {
		{"close", dpkghook_new_close, (void**)&dpkghook_orig_close},
		{"rmdir", dpkghook_new_rmdir, (void**)&dpkghook_orig_rmdir},
	};
	struct mach_header_64* header = _dyld_get_prog_image_header();
	rebind_symbols_image((void*)header, _dyld_get_image_slide(header), rebindings, sizeof(rebindings)/sizeof(rebindings[0]));
}