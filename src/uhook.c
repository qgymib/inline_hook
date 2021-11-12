#include "uhook.h"
#include <string.h>
#include "once.h"

#include "os/elf.h"

#include "arch/arm.h"
#include "arch/x86_64.h"

#define INLINE_HOOK_DEBUG
#include "log.h"

#define UHOOK_ATTR_INLINE   1
#define UHOOK_ATTR_GOTPLT   2

typedef int (*uhook_inject_fn)(void** token, void** fcall, void* target, void* detour);
typedef void (*uhook_uninject_fn)(void* token);

int uhook_inject(uhook_token_t* token, void* target, void* detour)
{
    void* inject_token = NULL;
    void* inject_call = NULL;

    uhook_inject_fn fn_inject =
#if defined(__i386__) || defined(__amd64__) || defined(_M_IX86) || defined(_M_AMD64)
        uhook_x86_64_inject
#elif defined(__arm__)
        uhook_arm_inject
#else
#   error "unsupport hardware platform"
        NULL
#endif
    ;

    int ret = fn_inject(&inject_token, &inject_call, target, detour);
    if (ret != UHOOK_SUCCESS)
    {
        return ret;
    }

    token->fcall = inject_call;
    token->token = inject_token;
    token->attrs = UHOOK_ATTR_INLINE;

    return UHOOK_SUCCESS;
}

int uhook_inject_got(uhook_token_t* token, const char* name, void* detour)
{
    void* inject_token = NULL;
    void* inject_call = NULL;
    int ret = elf_inject_got_patch(&inject_token, &inject_call, name, detour);

    if (ret != UHOOK_SUCCESS)
    {
        return ret;
    }

    token->fcall = inject_call;
    token->attrs = UHOOK_ATTR_GOTPLT;
    token->token = inject_token;

    return UHOOK_SUCCESS;
}

void uhook_uninject(uhook_token_t* token)
{
    uhook_uninject_fn fn_uninject = 
#if defined(__i386__) || defined(__amd64__) || defined(_M_IX86) || defined(_M_AMD64)
        uhook_x86_64_uninject
#elif defined(__arm__)
        uhook_arm_uninject
#else
#   error "unsupport hardware platform"
        NULL
#endif
        ;

    if (token->attrs & UHOOK_ATTR_GOTPLT)
    {
        elf_inject_got_unpatch(token->token);
        goto fin;
    }

    if (token->attrs & UHOOK_ATTR_INLINE)
    {
        fn_uninject(token->token);
        goto fin;
    }

fin:
    memset(token, 0, sizeof(*token));
}
