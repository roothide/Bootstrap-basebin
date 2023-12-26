#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <assert.h>
#include <mach-o/loader.h>
#include "common.h"

struct _dyld_interpose {
    void* hook;
    void* orig;
}* dyld_interpose_array=NULL;
int dyld_interpose_count=0;


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

static void perform_rebinding_with_section(section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];


    void* orig = indirect_symbol_bindings[i];
#if __has_feature(ptrauth_calls)
    orig = ptrauth_strip(orig, ptrauth_key_asia);
#endif

      for (uint j = 0; j < dyld_interpose_count; j++) {
        if (symbol_name_longer_than_1 && orig==dyld_interpose_array[j].orig) {
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
            void* newf = dyld_interpose_array[j].hook;
#if __has_feature(ptrauth_calls)
            newf = (void *)ptrauth_strip(newf, ptrauth_key_asia);
            newf = ptrauth_sign_unauthenticated(newf, ptrauth_key_asia, &(indirect_symbol_bindings[i]));
#endif
            indirect_symbol_bindings[i] = newf;
          }

        }
      }

  }
}

static void rebind_symbols_for_image(const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(sect, slide, symtab, strtab, indirect_symtab);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}


void load_interpose(struct mach_header_64* header)
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
                         ((strncmp(sec[j].segname, "__DATA", 6) == 0) || strncmp(sec[j].segname, "__AUTH", 6) == 0)) ) 
                    {
                        dyld_interpose_count = sec[j].size / sizeof(dyld_interpose_array[0]);
                        *(void**)&dyld_interpose_array = (void*)((uint64_t)header + sec[j].addr);
                        break;
                    }   
                }
            }
		}
        
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
	}
}


void* __current_module=NULL;
void interpose_bind(const struct mach_header *header, intptr_t slide)
{
    if(header == __current_module) return;
    
    rebind_symbols_for_image(header, slide);
}

void __interpose()
{
	struct dl_info di={0};
    dladdr((void*)__interpose, &di);

    __current_module = di.dli_fbase;

    struct mach_header_64* header = __current_module;
    
    load_interpose(header);

    assert(dyld_interpose_count>0 && dyld_interpose_array);

    _dyld_register_func_for_add_image(interpose_bind);

}
