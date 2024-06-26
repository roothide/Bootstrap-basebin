#include "CodeDirectory.h"
#include "CSBlob.h"
#include "Util.h"
#include <stddef.h>
#include <assert.h>

void csd_code_directory_read_slot_hash(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot, uint8_t *slotHashOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    csd_blob_read(codeDirBlob, codeDir.hashOffset + (slot * codeDir.hashSize), codeDir.hashSize, slotHashOut);
}

bool csd_code_directory_calculate_page_hash(CS_CodeDirectory* codeDir, MachO *macho, int slot, uint8_t *pageHashOut)
{
    // printf("csd_code_directory_calculate_page_hash %p %p %d %p\n", codeDirBlob, macho, slot, pageHashOut);
    // CS_CodeDirectory codeDir;
    // csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    // CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    uint32_t pageSize = (uint32_t)(pow(2.0, (double)(codeDir->pageSize)));
    uint32_t pageToReadSize = pageSize;
    uint32_t pageToReadOffset = slot * pageToReadSize;
    // printf("%x %x\n", pageToReadSize, pageToReadOffset);

    uint32_t csOffset = 0, csSize = 0;
    macho_find_code_signature_bounds(macho, &csOffset, &csSize);

    if (pageToReadOffset > csOffset) {
        printf("hash page overflow code_signature!\n");
        return false;
    }

    // Special case for reading the code signature itself
    if((pageToReadOffset + pageToReadSize) > csOffset) {
        if(slot != (codeDir->nCodeSlots - 1)) {
            printf("nCodeSlots mismatch!\n");
            return false;
        }
        pageToReadSize = csOffset - pageToReadOffset;
    }

    // Bail out when past EOF
    if ((pageToReadOffset + pageToReadSize) > memory_stream_get_size(macho_get_stream(macho))) return false;

    uint8_t page[pageToReadSize];
    if (macho_read_at_offset(macho, pageToReadOffset, pageToReadSize, page) != 0) return false;
    switch (codeDir->hashType) {
        case CS_HASHTYPE_SHA160_160: {
            CC_SHA1(page, (CC_LONG)pageToReadSize, pageHashOut);
            break;
        }

        case CS_HASHTYPE_SHA256_256:
        case CS_HASHTYPE_SHA256_160: {
            uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(page, (CC_LONG)pageToReadSize, fullHash);
            memcpy(pageHashOut, fullHash, codeDir->hashSize);
            break;
        }

        case CS_HASHTYPE_SHA384_384: {
            uint8_t fullHash[CC_SHA384_DIGEST_LENGTH];
            CC_SHA384(page, (CC_LONG)pageToReadSize, fullHash);
            memcpy(pageHashOut, fullHash, codeDir->hashSize);
            break;
        }

        default: {
            return false;
        }
    }
    return true;
}

bool csd_code_directory_verify_code_slot(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    uint8_t slotHash[codeDir.hashSize];
    csd_code_directory_read_slot_hash(codeDirBlob, macho, slot, slotHash);

    uint8_t pageHash[codeDir.hashSize];
    if (!csd_code_directory_calculate_page_hash(&codeDir, macho, slot, slotHash)) return false;

    return (memcmp(slotHash, pageHash, codeDir.hashSize) == 0);
}

bool csd_code_directory_verify_code_slots(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);

    for (int i = 0; i < codeDir.nCodeSlots; i++) {
        if (!csd_code_directory_verify_code_slot(codeDirBlob, macho, i)) {
            return false;
        }
    }
    return true;
}

const char *cs_hash_type_to_string(int hashType)
{
    switch (hashType) {
    case CS_HASHTYPE_SHA160_160:
        return "SHA-1 160";
    case CS_HASHTYPE_SHA256_256:
        return "SHA-2 256";
    case CS_HASHTYPE_SHA256_160:
        return "SHA-2 160";
    case CS_HASHTYPE_SHA384_384:
        return "SHA-3 384";
    default:
        return "Unknown blob type";
    }
}

const char* cs_slot_to_string(int slot)
{
    switch (slot) {
        case -11:
        return "Loaded library launch constraints hash";
        case -10:
        return "Responsible process launch constraints hash";
        case -9:
        return "Parent process launch constraints hash";
        case -8:
        return "Process launch constraints hash";
        case -7:
        return "DER entitlements hash";
        case -6:
        return "DMG signature hash";
        case -5:
        return "Entitlements hash";
        case -4:
        return "App-specific hash";
        case -3:
        return "CodeResources hash";
        case -2:
        return "Requirements blob hash";
        case -1:
        return "Info.plist hash";
        default:
        return "Page hash";
    }
}

char *csd_code_directory_copy_identity(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    if (codeDir.identOffset == 0) return NULL;

    char *identity = NULL;
    csd_blob_read_string(codeDirBlob, codeDir.identOffset, &identity);
    if (offsetOut) *offsetOut = codeDir.identOffset;
    return identity;
}

char *csd_code_directory_copy_team_id(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    if (codeDir.teamOffset == 0) return NULL;

    char *teamId = NULL;
    csd_blob_read_string(codeDirBlob, codeDir.teamOffset, &teamId);
    if (offsetOut) *offsetOut = codeDir.teamOffset;
    return teamId;
}

int csd_code_directory_set_team_id(CS_DecodedBlob *codeDirBlob, char *newTeamID)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    size_t newTeamIDSize = strlen(newTeamID)+1;

    int32_t shift = 0;
    uint32_t initalTeamOffset = 0;
    char *previousTeamID = csd_code_directory_copy_team_id(codeDirBlob, &initalTeamOffset);
    if (previousTeamID) {
        // If there is already a TeamID, delete it
        uint32_t previousTeamIDSize = strlen(previousTeamID)+1;
        csd_blob_delete(codeDirBlob, initalTeamOffset, previousTeamIDSize);
        shift -= previousTeamIDSize;
        free(previousTeamID);
    }

    if (initalTeamOffset) {
        codeDir.teamOffset = initalTeamOffset;
    }
    else {
        uint32_t identityOffset = 0;
        char *identity = csd_code_directory_copy_identity(codeDirBlob, &identityOffset);
        if (!identity) {
            // TODO: handle this properly
            // Calculate size of initial cd struct and place teamID after that
            return -1;
        }
        codeDir.teamOffset = identityOffset + strlen(identity) + 1;
        free(identity);
    }

    // Insert new team ID
    csd_blob_insert(codeDirBlob, codeDir.teamOffset, newTeamIDSize, newTeamID);
    shift += newTeamIDSize;

    // Shift other offsets as needed (Since we inserted data in the middle)
    if (codeDir.hashOffset != 0 && codeDir.hashOffset > initalTeamOffset) {
        codeDir.hashOffset += shift;
    }
    if (codeDir.scatterOffset != 0 && codeDir.scatterOffset > initalTeamOffset) {
        codeDir.scatterOffset += shift;
    }

    // Write changes to codeDir struct
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
    csd_blob_write(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    return 0;
}

uint32_t csd_code_directory_get_flags(CS_DecodedBlob *codeDirBlob)
{
    uint32_t flags = 0;
    csd_blob_read(codeDirBlob, offsetof(CS_CodeDirectory, flags), sizeof(flags), &flags);
    return BIG_TO_HOST(flags);
}

void csd_code_directory_set_flags(CS_DecodedBlob *codeDirBlob, uint32_t flags)
{
    flags = HOST_TO_BIG(flags);
    csd_blob_write(codeDirBlob, offsetof(CS_CodeDirectory, flags), sizeof(flags), &flags); 
}

uint8_t csd_code_directory_get_hash_type(CS_DecodedBlob *codeDirBlob)
{
    uint8_t hashType = 0;
    csd_blob_read(codeDirBlob, offsetof(CS_CodeDirectory, hashType), sizeof(hashType), &hashType);
    return hashType;
}

void csd_code_directory_set_hash_type(CS_DecodedBlob *codeDirBlob, uint8_t hashType)
{
    csd_blob_write(codeDirBlob, offsetof(CS_CodeDirectory, hashType), sizeof(hashType), &hashType);
}

int csd_code_directory_print_content(CS_DecodedSuperBlob *decodedSuperblob, CS_DecodedBlob *codeDirBlob, MachO *macho, bool printSlots, bool verifySlots)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);

    printf("Code directory:\n");
    printf("\tMagic: 0x%X\n", codeDir.magic);
    printf("\tLength: 0x%x\n", codeDir.length);
    printf("\tVersion: 0x%x\n", codeDir.version);
    printf("\tFlags: 0x%x\n", codeDir.flags);
    printf("\tHash offset: 0x%x\n", codeDir.hashOffset);
    printf("\tIdentity offset: 0x%x\n", codeDir.identOffset);
    printf("\tNumber of special slots: %u\n", codeDir.nSpecialSlots);
    printf("\tNumber of code slots: %u\n", codeDir.nCodeSlots);
    printf("\tCode limit: 0x%x\n", codeDir.codeLimit);
    printf("\tHash size: 0x%x\n", codeDir.hashSize);
    printf("\tHash type: %s\n", cs_hash_type_to_string(codeDir.hashType));
    printf("\tPage size: 0x%x\n", codeDir.pageSize);
    printf("\tspare2: 0x%x\n", codeDir.spare2);
    printf("\tScatter offset: 0x%x\n", codeDir.scatterOffset);
    printf("\tTeam offset: 0x%x\n", codeDir.teamOffset);

    int maxdigits = count_digits(codeDir.nCodeSlots);
    bool codeSlotsCorrect = true;
    for (int64_t i = -((int64_t)codeDir.nSpecialSlots); i < (int64_t)codeDir.nCodeSlots; i++) {
        // Read slot
        uint8_t slotHash[codeDir.hashSize];
        csd_code_directory_read_slot_hash(codeDirBlob, macho, i, slotHash);
        if (printSlots || verifySlots) {
            // Print the slot number
            printf("%*s%lld: ", maxdigits-count_digits(i), "", i);

            print_hash(slotHash, codeDir.hashSize);

            // Check if hash is just zeroes
            bool isZero = true;
            for (int j = 0; j < codeDir.hashSize; j++) {
                if (slotHash[j] != 0) {
                    isZero = false;
                    break;
                }
            }

            // TrollStore TODO: Validate that hashes are correct
            // validateHashes(macho, specialSlots, codeDir.nSpecialSlots * codeDir.hashSize);
            // Don't print the slot name if the hash is just zeroes
            if (!isZero) {
                // Print the special slot name (if applicable)
                printf(" (%s%s)", i==(codeDir.nCodeSlots-1)?"Special ":"", cs_slot_to_string(i));
            }
            printf("\n");
        }

        CS_DecodedBlob* blob = csd_superblob_find_blob(decodedSuperblob, -i, NULL);
        if (blob && verifySlots && i < 0) {
            int blobsize=csd_blob_get_size(blob);
            CS_GenericBlob *genblob = malloc(blobsize);
            memset(genblob, 0, blobsize);
            memory_stream_read(blob->stream, 0, blobsize, genblob);

            void* data = genblob;
            int size = blobsize;


            bool correct = false;
            bool calcWorked = false;

            uint8_t hash[codeDir.hashSize];
            switch (codeDir.hashType) {
                case CS_HASHTYPE_SHA160_160: {
                    CC_SHA1(data, (CC_LONG)size, hash);
                    calcWorked = true;
                    break;
                }

                case CS_HASHTYPE_SHA256_256:
                case CS_HASHTYPE_SHA256_160: {
                    uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
                    CC_SHA256(data, (CC_LONG)size, fullHash);
                    memcpy(hash, fullHash, codeDir.hashSize);
                    calcWorked = true;
                    break;
                }

                case CS_HASHTYPE_SHA384_384: {
                    uint8_t fullHash[CC_SHA384_DIGEST_LENGTH];
                    CC_SHA384(data, (CC_LONG)size, fullHash);
                    memcpy(hash, fullHash, codeDir.hashSize);
                    calcWorked = true;
                    break;
                }
            }

            if (calcWorked) {
                correct = (memcmp(slotHash, hash, codeDir.hashSize) == 0);
            }

            if (correct) {
                printf(" ✅");
            }
            else {
                codeSlotsCorrect = false;
                if (!calcWorked) {
                    printf(" ❌  (unable to calculate, probably EOF?)");
                }
                else {
                    printf(" ❌  (should be: ");
                    print_hash(hash, codeDir.hashSize);
                    printf(")");
                }
            }
            printf("\n");
        }

        if (verifySlots && i >= 0) {
            uint8_t pageHash[codeDir.hashSize];
            bool correct = false;
            bool calcWorked = csd_code_directory_calculate_page_hash(&codeDir, macho, i, pageHash);
            if (calcWorked) {
                correct = (memcmp(slotHash, pageHash, codeDir.hashSize) == 0);
            }

            if (correct) {
                printf(" ✅");
            }
            else {
                codeSlotsCorrect = false;
                if (!calcWorked) {
                    printf(" ❌  (unable to calculate, probably EOF?)");
                }
                else {
                    printf(" ❌  (should be: ");
                    print_hash(pageHash, codeDir.hashSize);
                    printf(")");
                }
            }
            printf("\n");
        }
    }
    
    uint32_t codeSignatureOffset = 0;
    macho_find_code_signature_bounds(macho, &codeSignatureOffset, NULL);
    
    uint32_t pageSize = (uint32_t)(pow(2.0, (double)(codeDir.pageSize)));
    int pageCount = align_to_size(codeSignatureOffset, pageSize) / pageSize;
    if(pageCount != codeDir.nCodeSlots) {
        codeSlotsCorrect = false;
        printf(" ❌  page count mismatch: %d, should be %d\n", codeDir.nCodeSlots, pageCount);
    }

    if (verifySlots) {
        if (codeSlotsCorrect) {
            printf("All page hashes are valid!\n");
        }
        else {
            printf("Some page hashes are invalid!\n");
        }
    }

    return 0;
}

void csd_code_directory_alloc(CS_DecodedBlob *codeDirBlob, MachO *macho)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(CS_CodeDirectory), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    uint32_t codeSignatureOffset = 0;
    // There is an edge case where random hashes end up incorrect, so we rehash every page (except the final one) to be sure
    macho_find_code_signature_bounds(macho, &codeSignatureOffset, NULL);
    // printf("codeSignatureOffset=%x\n", codeSignatureOffset);
    
    uint32_t pageSize = (uint32_t)(pow(2.0, (double)(codeDir.pageSize)));
    uint64_t finalPageBoundary = align_to_size(codeSignatureOffset, pageSize);
    int pageCount = (finalPageBoundary / pageSize);
    assert(pageCount >= codeDir.nCodeSlots);
    for(int i=codeDir.nCodeSlots; i<pageCount; i++)
    {
        codeDir.nCodeSlots++;

        uint32_t offsetOfBlobToReplace = codeDir.hashOffset + (i * codeDir.hashSize);

        uint8_t pageHash[codeDir.hashSize];
        memset(pageHash, 0, codeDir.hashSize);
        // printf("new page hash [%d] @ %x\n",i,i*pageSize);
        csd_blob_insert(codeDirBlob, offsetOfBlobToReplace, codeDir.hashSize, pageHash);

        // Shift other offsets as needed (Since we inserted data in the middle)
        if (codeDir.identOffset != 0 && codeDir.identOffset >= offsetOfBlobToReplace) {
            codeDir.identOffset += codeDir.hashSize;
        }
        if (codeDir.scatterOffset != 0 && codeDir.scatterOffset >= offsetOfBlobToReplace) {
            codeDir.scatterOffset += codeDir.hashSize;
        }
        if (codeDir.teamOffset != 0 && codeDir.teamOffset >= offsetOfBlobToReplace) {
            codeDir.teamOffset += codeDir.hashSize;
        }
    }

    codeDir.codeLimit = codeSignatureOffset;

    // Write changes to codeDir struct
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
    csd_blob_write(codeDirBlob, 0, sizeof(codeDir), &codeDir);
}

void csd_code_directory_update(CS_DecodedBlob *codeDirBlob, MachO *macho)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(CS_CodeDirectory), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    uint32_t codeSignatureOffset = 0;
    // There is an edge case where random hashes end up incorrect, so we rehash every page (except the final one) to be sure
    macho_find_code_signature_bounds(macho, &codeSignatureOffset, NULL);
    // printf("codeSignatureOffset=%x\n", codeSignatureOffset);
    
    uint32_t pageSize = (uint32_t)(pow(2.0, (double)(codeDir.pageSize)));
    uint64_t finalPageBoundary = align_to_size(codeSignatureOffset, pageSize);
    int pageCount = (finalPageBoundary / pageSize);

    assert(pageCount == codeDir.nCodeSlots);
    for(int i=0; i<pageCount; i++)
    {
        uint32_t offsetOfBlobToReplace = codeDir.hashOffset + (i * codeDir.hashSize);

        uint8_t pageHash[codeDir.hashSize];
        assert(csd_code_directory_calculate_page_hash(&codeDir, macho, i, pageHash));
        // printf("page hash [%d] @ %x : ",i, i*pageSize); print_hash(pageHash, codeDir.hashSize);printf("\n");
        csd_blob_write(codeDirBlob, offsetOfBlobToReplace, codeDir.hashSize, pageHash);
    }
}