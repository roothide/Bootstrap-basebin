#include "codesign.h"
#include "coretrust_bug.h"
#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/FileStream.h>
#include <choma/MachOByteOrder.h>
#include <choma/Host.h>
#include <copyfile.h>

#define LOG(...) //printf(__VA_ARGS__)

int main(int argc, char *argv[]) {
	if (argc != 2) {
        printf("Usage: %s <rootfs-based path to macho>\n", argv[0]);
        return 1;
    }

    char *input = argv[argc-1];

    struct stat st;
    if(stat(input, &st) != 0) {
        perror("stat");
        return 2;
    }

    FAT *fat = fat_init_from_path(input);
    if (!fat) return 3;

    char *tempOut = strdup("/tmp/XXXXXX");
    int fdOut = mkstemp(tempOut);
    assert(fdOut >= 0);
    close(fdOut);

    LOG("temp output file: %s\n", tempOut);

    int archHeaderSize = 0;
    void* archHeaderBuffer = NULL;

    struct fat_header fatHeader={0};
    fat_read_at_offset(fat, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, BIG_TO_HOST_APPLIER);

    LOG("FAT magic: %08X, nfat_arch: %d\n", fatHeader.magic, fatHeader.nfat_arch);

    MemoryStream *outStream = file_stream_init_from_path(tempOut, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    assert(outStream);

    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64)
    {
        assert(fatHeader.nfat_arch == fat->slicesCount);

        memory_stream_write(outStream, 0, sizeof(fatHeader), &fatHeader);

        if(fatHeader.magic==FAT_MAGIC) {
            archHeaderSize = fatHeader.nfat_arch * sizeof(struct fat_arch);
            archHeaderBuffer = malloc(archHeaderSize);
            fat_read_at_offset(fat, sizeof(fatHeader), archHeaderSize, archHeaderBuffer);
            for(int i=0; i<fatHeader.nfat_arch; i++) {
                FAT_ARCH_APPLY_BYTE_ORDER(&((struct fat_arch*)archHeaderBuffer)[i], BIG_TO_HOST_APPLIER);
            }
        }
        else if(fatHeader.magic==FAT_MAGIC_64) {
            archHeaderSize = fatHeader.nfat_arch * sizeof(struct fat_arch_64);
            archHeaderBuffer = malloc(archHeaderSize);
            fat_read_at_offset(fat, sizeof(fatHeader), archHeaderSize, archHeaderBuffer);
            for(int i=0; i<fatHeader.nfat_arch; i++) {
                FAT_ARCH_64_APPLY_BYTE_ORDER(&((struct fat_arch_64*)archHeaderBuffer)[i], BIG_TO_HOST_APPLIER);
            }
        }

        memory_stream_write(outStream, sizeof(fatHeader), archHeaderSize, archHeaderBuffer);
    }

    for(int i=0; i<fat->slicesCount; i++)
    {
        MachO *macho = fat->slices[i];

        char *temp = NULL;
        MemoryStream *inStream = NULL;

        if(macho && macho->machHeader.cputype==CPU_TYPE_ARM64)
        {
            temp = strdup("/tmp/XXXXXX");
            int fd = mkstemp(temp);
            assert(fd >= 0);
            close(fd);

            LOG("Processing slice[%d] 0x%08X/0x%08X %s\n", i, macho->machHeader.cputype, macho->machHeader.cpusubtype, temp);

            MemoryStream *machoStream = macho_get_stream(macho);
            MemoryStream *tempFileStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
            memory_stream_copy_data(machoStream, 0, tempFileStream, 0, memory_stream_get_size(machoStream));
            memory_stream_free(tempFileStream);

            LOG("Applying CoreTrust bypass to slice[%d] 0x%08X/0x%08X ...\n", i, macho->machHeader.cputype, macho->machHeader.cpusubtype);
            if (apply_coretrust_bypass(temp) != 0) {
                fprintf(stderr, "Failed applying CoreTrust bypass on slice[%d] 0x%08X/0x%08X\n", i, macho->machHeader.cputype, macho->machHeader.cpusubtype);
                return 5;
            }

            inStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_SIZE_AUTO);
            assert(inStream != NULL);
        }
        else
        {
            int offset,size;
            if(fatHeader.magic==FAT_MAGIC) {
                offset = ((struct fat_arch*)archHeaderBuffer)[i].offset;
                size = ((struct fat_arch*)archHeaderBuffer)[i].size;
            }
            else if(fatHeader.magic==FAT_MAGIC_64) {
                offset = ((struct fat_arch_64*)archHeaderBuffer)[i].offset;
                size = ((struct fat_arch_64*)archHeaderBuffer)[i].size;
            }
            inStream = file_stream_init_from_path(input, offset, size, 0);
            assert(inStream != NULL);
        }

        LOG("inStream size: 0x%zx, outStream size: 0x%zx\n", memory_stream_get_size(inStream), memory_stream_get_size(outStream));

        uint64_t alignMask = 0;
        uint64_t alignedSize = 0;

        if(fatHeader.magic==FAT_MAGIC) {
            alignMask = 1 << ((struct fat_arch*)archHeaderBuffer)[i].align;
            alignedSize = (memory_stream_get_size(outStream) + alignMask - 1) & (-alignMask);
            ((struct fat_arch*)archHeaderBuffer)[i].size = memory_stream_get_size(inStream);
            ((struct fat_arch*)archHeaderBuffer)[i].offset = alignedSize;
        }
        else if(fatHeader.magic==FAT_MAGIC_64) {
            alignMask = 1 << ((struct fat_arch_64*)archHeaderBuffer)[i].align;
            alignedSize = (memory_stream_get_size(outStream) + alignMask - 1) & (-alignMask);
            ((struct fat_arch_64*)archHeaderBuffer)[i].size = memory_stream_get_size(inStream);
            ((struct fat_arch_64*)archHeaderBuffer)[i].offset = alignedSize;
        }

        if(archHeaderBuffer)
        {
            LOG("alignMask=0x%llx, alignedSize=0x%llx, file size=0x%llX\n", alignMask, alignedSize, memory_stream_get_size(outStream));
            int filesize = memory_stream_get_size(outStream);
            for(int pad=filesize; pad<alignedSize; pad++) {
                uint8_t zero = 0;
                memory_stream_write(outStream, pad, 1, &zero);
            }
            assert(memory_stream_get_size(outStream) == alignedSize);
        }

        memory_stream_copy_data(inStream, 0, outStream, memory_stream_get_size(outStream), memory_stream_get_size(inStream));
        memory_stream_free(inStream);
        if(temp) {
            assert(unlink(temp) == 0);
            free(temp);
            temp=NULL;
        }
    }

    if (archHeaderBuffer)
    {
        if(fatHeader.magic==FAT_MAGIC) {
            for(int i=0; i<fatHeader.nfat_arch; i++) {
                FAT_ARCH_APPLY_BYTE_ORDER(&((struct fat_arch*)archHeaderBuffer)[i], HOST_TO_BIG_APPLIER);
            }
        }
        else if(fatHeader.magic==FAT_MAGIC_64) {
            for(int i=0; i<fatHeader.nfat_arch; i++) {
                FAT_ARCH_64_APPLY_BYTE_ORDER(&((struct fat_arch_64*)archHeaderBuffer)[i], HOST_TO_BIG_APPLIER);
            }
        }

        memory_stream_write(outStream, sizeof(fatHeader), archHeaderSize, archHeaderBuffer);

        FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, HOST_TO_BIG_APPLIER);
        memory_stream_write(outStream, 0, sizeof(fatHeader), &fatHeader);

        free(archHeaderBuffer);
        archHeaderBuffer = NULL;
        archHeaderSize = 0;
    }

    memory_stream_free(outStream);

    fat_free(fat);

    if (copyfile(tempOut, input, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) != 0) {
        perror("copyfile");
        return 4;
    }

    assert(chown(input, st.st_uid, st.st_gid)==0);
    assert(chmod(input, st.st_mode)==0);
    LOG("Applied CoreTrust Bypass!\n");

    free(tempOut);

    return 0;
}