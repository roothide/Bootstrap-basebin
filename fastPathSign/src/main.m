#include "codesign.h"
#include "coretrust_bug.h"
#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/FileStream.h>
#include <choma/Host.h>
#include <copyfile.h>

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);
    if (!macho) return NULL;
    
    char *temp = strdup("/tmp/XXXXXX");
    int fd = mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    close(fd);
    return temp;
}

int apply_coretrust_bypass_wrapper(const char *inputPath, const char *outputPath)
{
    char *machoPath = extract_preferred_slice(inputPath);
    if(!machoPath) {
        printf("extracted failed %s\n", inputPath);
        return -1;
    }
    printf("extracted best slice to %s\n", machoPath);

    int r = apply_coretrust_bypass(machoPath);
    if (r != 0) {
        free(machoPath);
        return r;
    }

    r = copyfile(machoPath, outputPath, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK);
    if (r == 0) {
        chmod(outputPath, 0755);
        printf("Signed file! CoreTrust bypass eta now!!\n");
    }
    else {
        perror("copyfile");
    }

    free(machoPath);
    return r;
}


int main(int argc, char *argv[]) {
	if (argc < 2) return -1;

    char *input = argv[argc-1];

    struct stat st;
    assert(stat(input, &st) == 0);

    // NSDictionary *customEntitlements = nil;
    // if (argc == 4) {
    //     if (!strcmp(argv[1], "--entitlements")) {
    //         NSString *entitlementsPath = [NSString stringWithUTF8String:argv[2]];
    //         customEntitlements = [NSDictionary dictionaryWithContentsOfFile:entitlementsPath];
    //     }
    // }

    // int r = codesign_sign_adhoc(input, true, customEntitlements);
	// if (r != 0) {
	// 	printf("Failed adhoc signing (%d) Continuing anyways...\n", r);
	// }
    // else {
    //     printf("AdHoc signed file!\n");
    // }

	char *machoPath = extract_preferred_slice(input);
	printf("Extracted best slice to %s\n", machoPath);

    printf("Applying CoreTrust bypass...\n");

	if (apply_coretrust_bypass(machoPath) != 0) {
		printf("Failed applying CoreTrust bypass\n");
		return -1;
	}

   if (copyfile(machoPath, input, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) == 0) {
        assert(chown(input, st.st_uid, st.st_gid)==0);
        assert(chmod(input, st.st_mode)==0);
        printf("Applied CoreTrust Bypass!\n");
    }
    else {
        perror("copyfile");
		return -1;
    }

    //keep owner, but codesign cached...

    // int src = open(machoPath, O_RDONLY);
    // assert(src != -1);

    // int dst = open(input, O_RDWR);
    // assert(dst != -1);

    // ftruncate(dst, 0);

    // int readlen;
    // char readbuf[128];
    // while( (readlen=read(src, readbuf, sizeof(readbuf))) > 0)
    //     write(dst, readbuf, readlen);

    // close(dst);
    // close(src);

    // assert(remove(machoPath) == 0);
    
    // //SecCode may strip suid so we need to restore it
    // assert(chmod(input, st.st_mode) == 0);

	free(machoPath);
	return 0;
}