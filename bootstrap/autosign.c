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


void machoEnumerateArchs(FILE* machoFile, void (^archEnumBlock)(struct fat_arch* arch, uint32_t archMetadataOffset, uint32_t archOffset, bool* stop))
{
	struct mach_header_64 mh;
	fseek(machoFile,0,SEEK_SET);
	fread(&mh,sizeof(mh),1,machoFile);
	
	if(mh.magic == FAT_MAGIC || mh.magic == FAT_CIGAM)
	{
		struct fat_header fh;
		fseek(machoFile,0,SEEK_SET);
		fread(&fh,sizeof(fh),1,machoFile);
		
		for(int i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++)
		{
			uint32_t archMetadataOffset = sizeof(fh) + sizeof(struct fat_arch) * i;
			struct fat_arch fatArch;
			fseek(machoFile, archMetadataOffset, SEEK_SET);
			fread(&fatArch, sizeof(fatArch), 1, machoFile);
			
			bool stop = false;
			archEnumBlock(&fatArch, archMetadataOffset, OSSwapBigToHostInt32(fatArch.offset), &stop);
			if(stop) break;
		}
	}
	else if(mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64)
	{
		bool stop;
		archEnumBlock(NULL, 0, 0, &stop);
	}
}

void machoGetInfo(FILE* candidateFile, bool *isMachoOut, bool *isLibraryOut)
{
	if (!candidateFile) return;

	struct mach_header_64 mh;
	fseek(candidateFile,0,SEEK_SET);
	fread(&mh,sizeof(mh),1,candidateFile);

	bool isMacho = mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64 || mh.magic == FAT_MAGIC || mh.magic == FAT_CIGAM;
	bool isLibrary = false;
	if (isMacho && isLibraryOut) {
		__block int32_t anyArchOffset = 0;
		machoEnumerateArchs(candidateFile, ^(struct fat_arch* arch, uint32_t archMetadataOffset, uint32_t archOffset, bool* stop) {
			anyArchOffset = archOffset;
			*stop = true;
		});

		fseek(candidateFile, anyArchOffset, SEEK_SET);
		fread(&mh, sizeof(mh), 1, candidateFile);

		isLibrary = OSSwapLittleToHostInt32(mh.filetype) != MH_EXECUTE;
	}

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

#define BOOTSTRAP_INSTALL_NAME	"@loader_path/.jbroot/basebin/bootstrap.dylib"

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

int patch_executable(char* file, uint32_t offset)
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
    
    void* macho = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(macho == MAP_FAILED) {
        fprintf(stderr, "map %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }

    struct mach_header_64* header = (struct mach_header_64*)((uint64_t)macho + offset);

	int retval = patch_macho(header);

    munmap(macho, st.st_size);

    close(fd);

    return retval;
}

int autosign(char* path)
{
    FILE* fp = fopen(path, "rb");
    if(fp) {
        bool ismacho=false,islib=false;
        machoGetInfo(fp, &ismacho, &islib);
        
        if(ismacho) 
        {
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

    return dpkghook_orig_rmdir(path);
}