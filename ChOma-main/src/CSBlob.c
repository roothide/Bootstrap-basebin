#include "CSBlob.h"

#include "CodeDirectory.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "BufferedStream.h"
#include "MemoryStream.h"
#include "Util.h"
#include <mach-o/loader.h>
#include <stddef.h>

const char *cs_blob_magic_to_string(uint32_t magic)
{
    switch (magic) {
    case CSMAGIC_REQUIREMENT:
        return "Requirement blob";
    case CSMAGIC_REQUIREMENTS:
        return "Requirements blob";
    case CSMAGIC_CODEDIRECTORY:
        return "Code directory blob";
    case CSMAGIC_EMBEDDED_SIGNATURE:
        return "Embedded signature blob";
    case CSMAGIC_EMBEDDED_SIGNATURE_OLD:
        return "Embedded signature blob (old)";
    case CSMAGIC_EMBEDDED_ENTITLEMENTS:
        return "Entitlements blob";
    case CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
        return "DER entitlements blob";
    case CSMAGIC_DETACHED_SIGNATURE:
        return "Detached signature blob";
    case CSMAGIC_BLOBWRAPPER:
        return "Signature blob";
    case CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT:
        return "Launchd contraint blob";
    default:
        return "Unknown blob type";
    }
}

const char *cs_slot_type_to_string(uint32_t slotType)
{
    if (slotType & CSSLOT_ALTERNATE_CODEDIRECTORIES) {
        int num = slotType & 0xfff;
        switch (num) {
        case 0:
            return "Alternate code directory slot (1)";
        case 1:
            return "Alternate code directory slot (2)";
        case 2:
            return "Alternate code directory slot (3)";
        case 3:
            return "Alternate code directory slot (4)";
        case 4:
            return "Alternate code directory slot (5)";
        default:
            return "Alternate code directory slot (invalid)";
        }
    }

    switch (slotType) {
    case CSSLOT_CODEDIRECTORY:
        return "Code directory slot";
    case CSSLOT_INFOSLOT:
        return "Info slot";
    case CSSLOT_REQUIREMENTS:
        return "Requirements slot";
    case CSSLOT_RESOURCEDIR:
        return "Resource Dir slot";
    case CSSLOT_APPLICATION:
        return "Application slot";
    case CSSLOT_ENTITLEMENTS:
        return "Entitlements slot";
    case CSSLOT_DER_ENTITLEMENTS:
        return "DER entitlements slot";
    case CSSLOT_LAUNCH_CONSTRAINT_SELF:
        return "Launch constraint slot (self)";
    case CSSLOT_LAUNCH_CONSTRAINT_PARENT:
        return "Launch constraint slot (parent)";
    case CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE:
        return "Launch constraint slot (responsible)";
    case CSSLOT_LIBRARY_CONSTRAINT:
        return "Library constraint slot";
    case CSSLOT_SIGNATURESLOT:
        return "Signature slot";
    case CSSLOT_IDENTIFICATIONSLOT:
        return "Identification slot";
    case CSSLOT_TICKETSLOT:
        return "Ticket slot";
    default:
        return "Unknown blob type";
    }
}

int macho_parse_signature_blob_to_der_encoded_data(MachO *macho, uint32_t signatureBlobOffset, uint32_t signatureBlobLength, void *outputDER)
{
    return macho_read_at_offset(macho, signatureBlobOffset + 8, signatureBlobLength - 8, outputDER);
}

int macho_find_code_signature_bounds(MachO *macho, uint32_t *offsetOut, uint32_t *sizeOut)
{
    __block int r = -1;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER);
            if (offsetOut) *offsetOut = csLoadCommand->dataoff;
            if (sizeOut) *sizeOut = csLoadCommand->datasize;
            *stop = true;
            r = 0;
        }
    });
    return r;
}

CS_SuperBlob *macho_read_code_signature(MachO *macho)
{
    uint32_t offset = 0, size = 0;
    if (macho_find_code_signature_bounds(macho, &offset, &size) == 0) {
        CS_SuperBlob *dataOut = malloc(size);
        macho_read_at_offset(macho, offset, size, dataOut);
        return dataOut;
    }
    return NULL;
}

int macho_replace_code_signature(MachO *macho, CS_SuperBlob *superblob)
{
    uint32_t csSegmentOffset = 0, csSegmentSize = 0;
    macho_find_code_signature_bounds(macho, &csSegmentOffset, &csSegmentSize);

    uint32_t sizeOfCodeSignature = 0;
    memory_stream_read(macho->stream, csSegmentOffset + offsetof(CS_SuperBlob, length), sizeof(sizeOfCodeSignature), &sizeOfCodeSignature);
    sizeOfCodeSignature = BIG_TO_HOST(sizeOfCodeSignature);

    uint64_t newCodeSignatureSize = BIG_TO_HOST(superblob->length);

    // See how much space we have to write the new code signature
    uint64_t entireFileSize = memory_stream_get_size(macho->stream);
    uint64_t freeSpace = entireFileSize - csSegmentOffset;
    // uint64_t paddingSize = freeSpace - sizeOfCodeSignature;
    // uint8_t* padding = malloc(paddingSize);
    // memset(padding, 0, paddingSize);

    if (newCodeSignatureSize >= freeSpace) {
        macho_write_at_offset(macho, csSegmentOffset, newCodeSignatureSize, superblob);
        // macho_write_at_offset(macho, csSegmentOffset + newCodeSignatureSize, paddingSize, padding);
    } else if (newCodeSignatureSize < freeSpace) {
        memory_stream_trim(macho_get_stream(macho), 0, entireFileSize-csSegmentOffset);
        macho_write_at_offset(macho, csSegmentOffset, newCodeSignatureSize, superblob);
        // macho_write_at_offset(macho, csSegmentOffset + newCodeSignatureSize, paddingSize, padding);
    }

    // free(padding);

    return 0;
}

int macho_extract_cs_to_file(MachO *macho, CS_SuperBlob *superblob)
{
    FILE *csDataFile = fopen("Code_Signature-Data", "wb+");
    fwrite(superblob, BIG_TO_HOST(superblob->length), 1, csDataFile);
    fclose(csDataFile);
    return 0;
}

CS_DecodedBlob *csd_blob_init(uint32_t type, CS_GenericBlob *blobData)
{
    CS_DecodedBlob *blob = malloc(sizeof(CS_DecodedBlob));
    if (!blob) return NULL;
    memset(blob, 0, sizeof(CS_DecodedBlob));

    blob->type = type;
    blob->stream = buffered_stream_init_from_buffer(blobData, BIG_TO_HOST(blobData->length), BUFFERED_STREAM_FLAG_AUTO_EXPAND);

    return blob;
}

int csd_blob_read(CS_DecodedBlob *blob, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(blob->stream, offset, size, outBuf);
}

static void _csd_blob_fix_length(CS_DecodedBlob *blob)
{
    uint32_t curSize = HOST_TO_BIG((uint32_t)memory_stream_get_size(blob->stream));
    memory_stream_write(blob->stream, offsetof(CS_GenericBlob, length), sizeof(curSize), &curSize);
}

int csd_blob_write(CS_DecodedBlob *blob, uint64_t offset, size_t size, const void *inBuf)
{
    int r = memory_stream_write(blob->stream, offset, size, inBuf);
    if (r == 0) _csd_blob_fix_length(blob);
    return r;
}

int csd_blob_insert(CS_DecodedBlob *blob, uint64_t offset, size_t size, const void *inBuf)
{
    int r = memory_stream_insert(blob->stream, offset, size, inBuf);
    if (r == 0) _csd_blob_fix_length(blob);
    return r;
}

int csd_blob_delete(CS_DecodedBlob *blob, uint64_t offset, size_t size)
{
    int r = memory_stream_delete(blob->stream, offset, size);
    if (r == 0) _csd_blob_fix_length(blob);
    return r;
}

int csd_blob_read_string(CS_DecodedBlob *blob, uint64_t offset, char **outString)
{
    return memory_stream_read_string(blob->stream, offset, outString);
}

int csd_blob_write_string(CS_DecodedBlob *blob, uint64_t offset, const char *string)
{
    int r = memory_stream_write_string(blob->stream, offset, string);
    if (r == 0) _csd_blob_fix_length(blob);
    return r;
}

int csd_blob_get_size(CS_DecodedBlob *blob)
{
    return memory_stream_get_size(blob->stream);
}

uint32_t csd_blob_get_type(CS_DecodedBlob *blob)
{
    return blob->type;
}

void csd_blob_set_type(CS_DecodedBlob *blob, uint32_t type)
{
    blob->type = type;
}

void csd_blob_free(CS_DecodedBlob *blob)
{
    if (blob->stream) {
        memory_stream_free(blob->stream);
    }
    free(blob);
}

CS_DecodedSuperBlob *csd_superblob_decode(CS_SuperBlob *superblob)
{
    CS_DecodedSuperBlob *decodedSuperblob = malloc(sizeof(CS_DecodedSuperBlob));
    if (!decodedSuperblob) return NULL;
    memset(decodedSuperblob, 0, sizeof(CS_DecodedSuperBlob));

    CS_DecodedBlob **nextBlob = &decodedSuperblob->firstBlob;
    decodedSuperblob->magic = BIG_TO_HOST(superblob->magic);

    for (uint32_t i = 0; i < BIG_TO_HOST(superblob->count); i++) {
        CS_BlobIndex curIndex = superblob->index[i];
        BLOB_INDEX_APPLY_BYTE_ORDER(&curIndex, BIG_TO_HOST_APPLIER);
        //printf("decoding %u (type: %x, offset: 0x%x)\n", i, curIndex.type, curIndex.offset);

        CS_GenericBlob *curBlobData = (CS_GenericBlob *)(((uint8_t*)superblob) + curIndex.offset);

        *nextBlob = csd_blob_init(curIndex.type, curBlobData);
        nextBlob = &(*nextBlob)->next;
    }
    return decodedSuperblob;
}

CS_SuperBlob *csd_superblob_encode(CS_DecodedSuperBlob *decodedSuperblob)
{
    uint32_t blobCount = 0, blobSize = 0;

    // Determine amount and size of contained blobs
    CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
    while (nextBlob) {
        blobCount++;
        blobSize += csd_blob_get_size(nextBlob);
        nextBlob = nextBlob->next;
    }

    uint32_t superblobLength = sizeof(CS_SuperBlob) + (sizeof(CS_BlobIndex) * blobCount) + blobSize;
    CS_SuperBlob *superblob = malloc(superblobLength);

    // Populate superblob fields
    superblob->count = blobCount;
    superblob->length = superblobLength;
    superblob->magic = decodedSuperblob->magic;
    SUPERBLOB_APPLY_BYTE_ORDER(superblob, HOST_TO_BIG_APPLIER)

    // Populate indexes and write actual backing data
    uint32_t idx = 0;
    uint32_t dataStartOffset = sizeof(CS_SuperBlob) + (sizeof(CS_BlobIndex) * blobCount);
    uint8_t *superblobData = ((uint8_t*)superblob) + dataStartOffset;
    uint8_t *superblobDataCur = superblobData;
    nextBlob = decodedSuperblob->firstBlob;
    while (nextBlob) {
        // Populate blob data
        uint32_t curSize = csd_blob_get_size(nextBlob);
        csd_blob_read(nextBlob, 0, curSize, superblobDataCur);

        // Populate index
        CS_BlobIndex *curIndex = &superblob->index[idx];
        curIndex->offset = dataStartOffset + (superblobDataCur - superblobData);
        curIndex->type = nextBlob->type;
        BLOB_INDEX_APPLY_BYTE_ORDER(curIndex, HOST_TO_BIG_APPLIER);

        superblobDataCur += curSize;
        idx++;
        nextBlob = nextBlob->next;
    }
    return superblob;
}

CS_DecodedBlob *csd_superblob_find_blob(CS_DecodedSuperBlob *superblob, uint32_t type, uint32_t *indexOut)
{
    CS_DecodedBlob *blob = superblob->firstBlob;
    uint32_t i = 0;
    while (blob) {
        if (blob->type == type) {
            if (indexOut) *indexOut = i;
            return blob;
        }
        blob = blob->next;
        i++;
    }
    return NULL;
}

int csd_superblob_insert_blob_after_blob(CS_DecodedSuperBlob *superblob, CS_DecodedBlob *blobToInsert, CS_DecodedBlob *afterBlob)
{
    blobToInsert->next = afterBlob->next;
    afterBlob->next = blobToInsert;
    return 0;
}

int csd_superblob_insert_blob_at_index(CS_DecodedSuperBlob *superblob, CS_DecodedBlob *blobToInsert, uint32_t atIndex)
{
    if (atIndex == 0) {
        blobToInsert->next = superblob->firstBlob;
        superblob->firstBlob = blobToInsert;
        return 0;
    }
    else {
        uint32_t i = 0;
        CS_DecodedBlob *blobAtIndex = superblob->firstBlob;
        while (blobAtIndex && i < atIndex) {
            blobAtIndex = blobAtIndex->next;
            i++;
        }
        if (blobAtIndex) {
            return csd_superblob_insert_blob_after_blob(superblob, blobToInsert, blobAtIndex);
        }
        return -1;
    }
}

int csd_superblob_append_blob(CS_DecodedSuperBlob *superblob, CS_DecodedBlob *blobToAppend)
{
    CS_DecodedBlob *lastBlob = superblob->firstBlob;
    while (lastBlob->next) {
        lastBlob = lastBlob->next;
    }
    return csd_superblob_insert_blob_after_blob(superblob, blobToAppend, lastBlob);
}

int csd_superblob_remove_blob(CS_DecodedSuperBlob *superblob, CS_DecodedBlob *blobToRemove)
{
    CS_DecodedBlob *blob = superblob->firstBlob;
    if (blob == blobToRemove) {
        superblob->firstBlob = blobToRemove->next;
        return 0;
    }
    while (blob) {
        if (blob->next == blobToRemove) {
            blob->next = blobToRemove->next;
            return 0;
        }
        blob = blob->next;
    }
    return -1;
}

int csd_superblob_remove_blob_at_index(CS_DecodedSuperBlob *superblob, uint32_t atIndex)
{
    if (atIndex == 0) {
        return csd_superblob_remove_blob(superblob, superblob->firstBlob);
    }
    else {
        uint32_t i = 0;
        CS_DecodedBlob *blobAtIndex = superblob->firstBlob;
        while (blobAtIndex && i < atIndex) {
            blobAtIndex = blobAtIndex->next;
            i++;
        }
        if (blobAtIndex) {
            int r = csd_superblob_remove_blob(superblob, blobAtIndex);
            if (r == 0) csd_blob_free(blobAtIndex);
            return r;
        }
        return -1;
    }
    return 0;
}

void write2file(char* path, void* data, int size)
{
    FILE* fp = fopen(path, "w");
    fwrite(data, size, 1, fp);
    fclose(fp);
}

int csd_superblob_print_content(CS_DecodedSuperBlob *decodedSuperblob, MachO *macho, bool printAllSlots, bool verifySlots)
{
    CS_DecodedBlob *currentBlob = decodedSuperblob->firstBlob;
    int count = 0;
    uint32_t offset = 0;
    while (currentBlob) {
        uint32_t blobType = currentBlob->type;
        printf("Slot %d: %s (type: 0x%x, offset 0x%x, size 0x%0x).\n", count++, cs_slot_type_to_string(blobType), blobType, offset, csd_blob_get_size(currentBlob));


        int blobsize=csd_blob_get_size(currentBlob);
        CS_GenericBlob *genblob = malloc(blobsize);
        memset(genblob, 0, blobsize);
        memory_stream_read(currentBlob->stream, 0, blobsize, genblob);
        GENERIC_BLOB_APPLY_BYTE_ORDER(genblob, BIG_TO_HOST_APPLIER);
        printf("magic=%08X(%s) length=0x%x\n", genblob->magic, cs_blob_magic_to_string(genblob->magic), genblob->length);

        char path[255];
        snprintf(path,sizeof(path),"/Users/admin/Downloads/%x.%s", blobType, cs_blob_magic_to_string(genblob->magic));
        write2file(path, genblob->data, genblob->length-sizeof(CS_GenericBlob));

        if (blobType == CSSLOT_CODEDIRECTORY || blobType == CSSLOT_ALTERNATE_CODEDIRECTORIES) {
            csd_code_directory_print_content(decodedSuperblob, currentBlob, macho, printAllSlots, verifySlots);
        }
        else if (blobType == CSSLOT_SIGNATURESLOT) {
            CS_GenericBlob *cms_blob = malloc(sizeof(CS_GenericBlob));
            memset(cms_blob, 0, sizeof(CS_GenericBlob));
            memory_stream_read(currentBlob->stream, 0, sizeof(CS_GenericBlob), cms_blob);
            GENERIC_BLOB_APPLY_BYTE_ORDER(cms_blob, BIG_TO_HOST_APPLIER);
            printf("This is the %s, magic %#x.\n", cs_blob_magic_to_string(cms_blob->magic), cms_blob->magic);
        }
        else if(blobType == CSSLOT_ENTITLEMENTS) {
            int blobsize=csd_blob_get_size(currentBlob);
            CS_GenericBlob *ent_blob = malloc(blobsize+1);
            memset(ent_blob, 0, blobsize+1);
            memory_stream_read(currentBlob->stream, 0, blobsize, ent_blob);
            GENERIC_BLOB_APPLY_BYTE_ORDER(ent_blob, BIG_TO_HOST_APPLIER);
            printf("This is the %s, magic %#x:\n%s\n\n", cs_blob_magic_to_string(ent_blob->magic), ent_blob->magic, &ent_blob->data[0]);
        }
        else {
            CS_GenericBlob *generic_blob = malloc(sizeof(CS_GenericBlob));
            memset(generic_blob, 0, sizeof(CS_GenericBlob));
            memory_stream_read(currentBlob->stream, 0, sizeof(CS_GenericBlob), generic_blob);
            GENERIC_BLOB_APPLY_BYTE_ORDER(generic_blob, BIG_TO_HOST_APPLIER);
            printf("This is the %s, magic %#x.\n", cs_blob_magic_to_string(generic_blob->magic), generic_blob->magic);
        }

        offset += csd_blob_get_size(currentBlob);
        currentBlob = currentBlob->next;
    }
    return 0;
}

void csd_superblob_free(CS_DecodedSuperBlob *decodedSuperblob)
{
    CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
    while (nextBlob) {
        CS_DecodedBlob *prevBlob = nextBlob;
        nextBlob = nextBlob->next;
        csd_blob_free(prevBlob);
    }
    free(decodedSuperblob);
}

int update_load_commands(MachO *macho, CS_SuperBlob *superblob, uint64_t originalSize) {
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        bool foundOne = false;
        if (loadCommand.cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
            if (strcmp(segmentCommand->segname, "__LINKEDIT") != 0) return;
            uint64_t difference = segmentCommand->filesize - originalSize;
            uint64_t newFileSize = (uint64_t)(superblob->length >> 0x10) + difference;
            uint64_t newVMSize = align_to_size(newFileSize, 0x4000);
            printf("Updating %s segment - offset: 0x%llx, filesize: 0x%llx, vmsize: 0x%llx.\n", segmentCommand->segname, segmentCommand->fileoff, newFileSize, newVMSize);
            *stop = foundOne;
            foundOne = true;
        }
        if (loadCommand.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER);
            csLoadCommand->datasize = superblob->length;
            // LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, HOST_TO_LITTLE_APPLIER);
            printf("Updating code signature load command - offset: 0x%x, size: 0x%x.\n", csLoadCommand->dataoff, HOST_TO_BIG(csLoadCommand->datasize));
            *stop = foundOne;
            foundOne = true;
        }
    });
    return 0;
}