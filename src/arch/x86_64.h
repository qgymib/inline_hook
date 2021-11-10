#ifndef __UHOOK_ARCH_X86_64_H__
#define __UHOOK_ARCH_X86_64_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"

API_LOCAL int uhook_x86_64_inject(void** token, void** fn_call, void* target, void* detour);
API_LOCAL void uhook_x86_64_uninject(void* token);

#ifdef __cplusplus
}
#endif
#endif
