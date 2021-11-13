#ifndef __UHOOK_OS_ELF_H__
#define __UHOOK_OS_ELF_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"
#include <stddef.h>
#include <stdint.h>

API_LOCAL int elf_inject_got_patch(void** token, void** fn_call, const char* name, void* detour);

API_LOCAL void elf_inject_got_unpatch(void* token);

API_LOCAL void* elf_get_relocation_by_addr(void* symbol);

API_LOCAL size_t elf_get_function_size(void* symbol);

API_LOCAL void uhook_dump_phdr(const char* dlname);

#ifdef __cplusplus
}
#endif
#endif
