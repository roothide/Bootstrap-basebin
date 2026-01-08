#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>

#include "common.h"

struct _dyld_interpose {
    void* hook;
    void* orig;
}* dyld_interpose_array=NULL;
int dyld_interpose_count=0;


static void perform_rebinding_with_section(section_t *section, intptr_t slide)
{
  SYSLOG("rebinding with section %s:%s\n", section->segname, section->sectname);

  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++)
  {
      void* symbol_pointer = indirect_symbol_bindings[i];
#if __has_feature(ptrauth_calls)
      symbol_pointer = ptrauth_strip(symbol_pointer, ptrauth_key_asia);
#endif

      for (uint j = 0; j < dyld_interpose_count; j++)
      {
        void* orig = dyld_interpose_array[j].orig;
        void* hook = dyld_interpose_array[j].hook;
#if __has_feature(ptrauth_calls)
        orig = ptrauth_strip(orig, ptrauth_key_asia);
        hook = ptrauth_strip(hook, ptrauth_key_asia);
#endif

        if (symbol_pointer == orig) {
          SYSLOG("[%s] orig %p==%p/%p hook=%p/%p\n", section->sectname, section->addr+i*sizeof(void*), orig, dyld_interpose_array[j].orig,orig, dyld_interpose_array[j].hook,hook);
          kern_return_t err;

          /**
           * 1. Moved the vm protection modifying codes to here to reduce the
           *    changing scope.
           * 2. Adding VM_PROT_WRITE mode unconditionally because vm_region
           *    API on some iOS/Mac reports mismatch vm protection attributes.
           * -- Lianfu Hao Jun 16th, 2021
           **/
          err = vm_protect (mach_task_self (), (uintptr_t)indirect_symbol_bindings, section->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          if (err == KERN_SUCCESS) {
            /**
             * Once we failed to change the vm protection, we
             * MUST NOT continue the following write actions!
             * iOS 15 has corrected the const segments prot.
             * -- Lionfore Hao Jun 11th, 2021
             **/
            if(indirect_symbol_bindings[i] == symbol_pointer) { //NO PAC
              indirect_symbol_bindings[i] = hook;
            }
#if __has_feature(ptrauth_calls)
            else if(indirect_symbol_bindings[i] == ptrauth_sign_unauthenticated(symbol_pointer, ptrauth_key_asia, 0)) { //PACIZA
              indirect_symbol_bindings[i] = ptrauth_sign_unauthenticated(hook, ptrauth_key_asia, 0);
            }
            else if(indirect_symbol_bindings[i] == ptrauth_sign_unauthenticated(symbol_pointer, ptrauth_key_asia, &(indirect_symbol_bindings[i]))) { //PACIA
              indirect_symbol_bindings[i] = ptrauth_sign_unauthenticated(hook, ptrauth_key_asia, &(indirect_symbol_bindings[i]));
            }
#endif
            SYSLOG("rebind %p -> %p\n", orig, hook);
          } else {
            SYSERR("vm_protect failed: %s\n", mach_error_string(err));
          }

        }
      }

  }
}

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *cur_seg_cmd = NULL;
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      // if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
      //     strcmp(cur_seg_cmd->segname, "__AUTH_CONST") != 0 &&
      //     strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
      //   continue;
      // }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(sect, slide);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(sect, slide);
        }
      }
    }
  }
}


void load_interpose(const struct mach_header_64* header, intptr_t slide)
{
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
                
        switch(lc->cmd) {

            case LC_SEGMENT_64: {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                
                SYSLOG("segment: %s file=%llx:%llx vm=%16llx:%16llx\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
                
                struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
                for(int j=0; j<seg->nsects; j++)
                {
                    SYSLOG("section[%d] = %s/%s offset=%x vm=%llx:%llx\n", j, sec[j].segname, sec[j].sectname,
                          sec[j].offset, sec[j].addr, sec[j].size);
                    
                    if ( ((sec[j].flags & SECTION_TYPE) == S_INTERPOSING)
                     || ((strcmp(sec[j].sectname, "__interpose") == 0) &&
                         ((strcmp(sec[j].segname, "__DATA") == 0) || strcmp(sec[j].segname, "__AUTH") == 0)) ) 
                    {
                        dyld_interpose_count = sec[j].size / sizeof(dyld_interpose_array[0]);
                        *(void**)&dyld_interpose_array = (void*)((uint64_t)slide + sec[j].addr);
                        SYSLOG("found interpose %p %d\n", dyld_interpose_array, dyld_interpose_count);
                        break;
                    }   

                    //found?
                    if(dyld_interpose_array) break;
                }
            }
        }
        
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
	}
}

extern intptr_t _dyld_get_image_slide(const struct mach_header_64* mh);
extern const char* dyld_image_path_containing_address(const void* addr);

void* __current_module=NULL;

void interpose_bind(const struct mach_header *header, intptr_t slide)
{
    if(header == __current_module) return;
    
    SYSLOG("interpose_bind %p %lx %s\n", header, slide, dyld_image_path_containing_address(header));
    rebind_symbols_for_image(header, slide);
}

void _dynamic_interpose()
{
	struct dl_info di={0};
    dladdr((void*)_dynamic_interpose, &di);

    __current_module = di.dli_fbase;

    const struct mach_header_64* header = __current_module;
    
    load_interpose(header, _dyld_get_image_slide(header));

    assert(dyld_interpose_array && dyld_interpose_count>0);

    _dyld_register_func_for_add_image(interpose_bind);
}
