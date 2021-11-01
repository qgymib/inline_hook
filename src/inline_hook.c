#include "inline_hook.h"
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>

#ifdef _WIN32
#   include <windows.h>
#else
#   include <stdint.h>
#   include <unistd.h>
#   include <sys/mman.h>
#endif

/**
 * @brief Cast a member of a structure out to the containing structure
 * @param[in] ptr       The pointer to the member.
 * @param[in] TYPE      The type of the container struct this is embedded in.
 * @param[in] member    The name of the member within the struct.
 * @return              The address of the containing structure
 */
#if !defined(container_of)
#   define container_of(ptr, TYPE, member)    \
        ((TYPE*)((uint8_t*)(ptr) - (size_t)&((TYPE*)0)->member))
#endif

#define INLINE_HOOK_DECLARE_INTERFACE(fn_inject, fn_uninject) \
    int inline_hook_inject(void** origin, void* target, void* detour) {\
        return fn_inject(origin, target, detour);\
    }\
    void inline_hook_uninject(void** origin) {\
        fn_uninject(origin);\
    }

static size_t _get_page_size(void)
{
#if defined(_WIN32)
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    unsigned long page_size = sys_info.dwPageSize;
#elif defined(__linux__)
    long page_size = sysconf(_SC_PAGE_SIZE);
#else
    long page_size = 0;
#endif

    return page_size <= 0 ? 4096 : page_size;
}

/**
 * @brief Get start address of page from given address.
 * @parm[in] addr           Address to calculate
 * @param[in] page_size     Page size
 * @return                  The start address of page
 */
static void* _page_of(void* addr, size_t page_size)
{
    return (char*)((uintptr_t)addr & ~(page_size - 1));
}

static int _modify_opcode(void* addr, size_t size, void (*callback)(void*), void* data)
{
    const size_t page_size = _get_page_size();

    int flag_failure = 0;
    uint8_t* start_addr = (uint8_t*)_page_of(addr, page_size);
    uint8_t* end_addr = (uint8_t*)addr + size;

    const size_t n_page = ((end_addr - start_addr - 1) / page_size) + 1;
    const size_t protect_size = page_size * n_page;

    /* Remove memory protect */
#if defined(_WIN32)
    DWORD lpflOldProtect;
    flag_failure = 0 == VirtualProtect(start_addr, protect_size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(start_addr, protect_size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
    if (flag_failure)
    {
        return -1;
    }

    /* call callback */
    callback(data);

    /* Add memory protect */
#if defined(_WIN32)
    flag_failure = 0 == VirtualProtect(start_addr, protect_size, PAGE_EXECUTE_READ, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(start_addr, protect_size, PROT_READ | PROT_EXEC);
#endif
    assert(flag_failure == 0);

    return 0;
}

#if defined(__i386__) || defined(__amd64__) || defined(_M_IX86) || defined(_M_AMD64)

typedef struct trampline_x86_64
{
    void*       addr_target;            /**< Target function address */
    void*       addr_detour;            /**< Detour function address */
    uint8_t     redirect_opcode[13];    /**< Opcode to redirect to detour function */
    uint8_t     backup_opcode[13];      /**< Original function code */
#if defined(_MSC_VER)
#   pragma warning(push)
#   pragma warning(disable: 4200)
#endif
    uint8_t     wrap_opcode[];          /**< Opcode to call original function */
#if defined(_MSC_VER)
#   pragma warning(pop)
#endif
}trampline_x86_64_t;

static void _x86_64_fill_jump_code_near(uint8_t jump_code[5], intptr_t addr_diff)
{
    /**
     * 5 byte(jmp rel32)
     */
    jump_code[0] = 0xE9;
    uint32_t code = (uint32_t)(addr_diff - 5);
    memcpy(&jump_code[1], &code, sizeof(code));
}

static void _x86_64_fill_jump_code_far(uint8_t jump_code[13], void* detour)
{
    /*
     * 13 byte(jmp m16:64)
     * movabs $0x102030405060708,%r11
     * jmpq   *%r11
     */
    jump_code[0] = 0x49;
    jump_code[1] = 0xbb;
    jump_code[10] = 0x41;
    jump_code[11] = 0xff;
    jump_code[12] = 0xe3;
    uint64_t code = (uint64_t)detour;
    memcpy(&jump_code[2], &code, sizeof(code));
}

static void _x86_64_fill_jump_code(uint8_t jump_code[13], void* target, void* detour)
{
    intptr_t addr_diff = (char*)detour - (char*)target;
    if (-(intptr_t)0x80000000 <= addr_diff && addr_diff < 0x80000000)
    {
        _x86_64_fill_jump_code_near(jump_code, addr_diff);
    }
    else
    {
        _x86_64_fill_jump_code_far(jump_code, detour);
    }
}

static void _x86_64_init_trampoline(trampline_x86_64_t* handle, uint8_t jump_code[13], void* target, void* detour)
{
    handle->addr_target = target;
    handle->addr_detour = detour;
    memcpy(handle->redirect_opcode, jump_code, sizeof(handle->redirect_opcode));

    if (jump_code[12] != 0)
    {
        // TODO add wrap code
    }
    else
    {
        // TODO add wrap code
    }
}

static void _x86_64_do_inject(void* arg)
{
    trampline_x86_64_t* handle = arg;

    size_t copy_size = handle->redirect_opcode[12] != 0 ? 13 : 5;
    memcpy(handle->addr_target, handle->redirect_opcode, copy_size);
}

static void _x86_64_undo_inject(void* arg)
{
    trampline_x86_64_t* handle = arg;

    size_t copy_size = handle->redirect_opcode[12] != 0 ? 13 : 5;
    memcpy(handle->addr_target, handle->backup_opcode, copy_size);
}

static int _x86_64_inline_hook_inject(void** origin, void* target, void* detour)
{
    uint8_t jump_code[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    _x86_64_fill_jump_code(jump_code, target, detour);

    trampline_x86_64_t* handle = calloc(1, sizeof(trampline_x86_64_t) + sizeof(uint8_t) * (13 * 2));
    if (handle == NULL)
    {
        goto err;
    }

    _x86_64_init_trampoline(handle, jump_code, target, detour);

    if (_modify_opcode(target, jump_code[12] != 0 ? 13 : 5, _x86_64_do_inject, handle) < 0)
    {
        free(handle);
        goto err;
    }

    *origin = handle->wrap_opcode;

    return 0;

err:
    *origin = NULL;
    return -1;
}

static void _x86_64_inline_hook_uninject(void** origin)
{
    trampline_x86_64_t* handle = container_of(*origin, trampline_x86_64_t, wrap_opcode);
    if (_modify_opcode(handle->addr_target, handle->redirect_opcode[12] != 0 ? 13 : 5, _x86_64_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }

    * origin = NULL;
}

INLINE_HOOK_DECLARE_INTERFACE(_x86_64_inline_hook_inject, _x86_64_inline_hook_uninject)

#elif defined(__ARM_ARCH_6T2__) ||\
    defined(__ARM_ARCH_7__) ||\
    defined(__ARM_ARCH_7A__) ||\
    defined(__ARM_ARCH_7R__) ||\
    defined(__ARM_ARCH_7M__) ||\
    defined(__ARM_ARCH_7S__) ||\
    defined(__aarch64__)
/**
 * @brief Hook context for arm64
 *
 * The jump code can be either 4 bytes (with address space < 32MB):
 * ```
 * b #(address)
 * ```
 * or 12 bytes (with any address space)
 * ```
 * mov  r0, #(lower 16 bit address)
 * movt r0, #(higher 16 bit address)
 * bx   r0
 * ```
 *
 * To know whether 12 bytes code is used, check if #trampoline_arm64_t::redirect_opcode[2]
 * is non-zero.
 */
typedef struct trampoline_arm64
{
    void*       addr_target;            /**< Target function address */
    void*       addr_detour;            /**< Detour function address */
    uint32_t    redirect_opcode[3];     /**< Opcode to redirect to detour function */
    uint32_t    backup_opcode[3];       /**< Original function code */
#if defined(_MSC_VER)
#   pragma warning(push)
#   pragma warning(disable: 4200)
#endif
    uint32_t    wrap_opcode[];          /**< Opcode to call original function */
#if defined(_MSC_VER)
#   pragma warning(pop)
#endif
}trampoline_arm64_t;

static void _reflash_insn_cache(void)
{
#if defined(__ARM_ARCH_6T2__) ||\
    defined(__ARM_ARCH_7__) ||\
    defined(__ARM_ARCH_7A__) ||\
    defined(__ARM_ARCH_7R__) ||\
    defined(__ARM_ARCH_7M__) ||\
    defined(__ARM_ARCH_7S__) ||\
    defined(__aarch64__)

    __asm__ __volatile__(
        "mov    r0, #0\n\t"
        "mcr    p15, 0, r0, c7, c1, 0\n\t"  /* invalidate I-cache inner shareable */
        "mcr    p15, 0, r0, c7, c5, 0"      /* I+BTB cache invalidate */
        :::"r0"
    );

#endif
}

static void _arm_fill_jump_code_near(uint32_t jump_code[1], intptr_t addr_diff)
{
    jump_code[0] = (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0xea000000;
}

static void _arm_fill_jump_code_far(uint32_t jump_code[3], void* dest)
{
    uint32_t _fn_stub_l = (uintptr_t)dest & 0x0000FFFF;
    uint32_t _fn_stub_h = ((uintptr_t)dest >> 16) & 0x0000FFFF;

    /* mov  r0, #(lower 16 bit address) */
    jump_code[0] = (_fn_stub_l & 0x00000FFF) | ((_fn_stub_l & 0x0000F000) << 4) | 0xe3000000;
    /* movt r0, #(higher 16 bit address) */
    jump_code[1] = (_fn_stub_h & 0x00000FFF) | ((_fn_stub_h & 0x0000F000) << 4) | 0xe3400000;
    /* bx   r0 */
    jump_code[2] = 0xe12fff10;
}

/**
 * @brief Generate jump code
 * @param[out] jump_code    The generated jump code
 * @param[in] target        The position where code will be executed
 * @param[in] detour        The destination address
 */
static void _arm_fill_jump_code(uint32_t jump_code[3], void* target, void* detour)
{
    intptr_t addr_diff = (intptr_t)detour - (intptr_t)target;
    if (-0x2000000 <= addr_diff && addr_diff < 0x2000000)
    {
        _arm_fill_jump_code_near(jump_code, addr_diff);
    }
    else
    {
        _arm_fill_jump_code_far(jump_code, detour);
    }
}

static void _arm_do_inject(void* arg)
{
    trampoline_arm64_t* handle = arg;

    size_t copy_size = (handle->redirect_opcode[2] != 0 ? 3 : 1) * sizeof(uint32_t);
    memcpy(handle->addr_target, handle->redirect_opcode, copy_size);
}

static void _arm_init_trampoline(trampoline_arm64_t* handle, uint32_t jump_code[3], void* target, void* detour)
{
    handle->addr_target = target;
    handle->addr_detour = detour;
    memcpy(handle->redirect_opcode, jump_code, sizeof(handle->redirect_opcode));

    uint32_t* p_target = target;
    if (jump_code[2] != 0)
    {
        memcpy(&handle->wrap_opcode[0], target, sizeof(uint32_t) * 3);
        _arm_fill_jump_code_far(&handle->wrap_opcode[3], &p_target[3]);
    }
    else
    {
        memcpy(&handle->wrap_opcode[0], target, sizeof(uint32_t) * 1);
        _arm_fill_jump_code_far(&handle->wrap_opcode[1], &p_target[1]);
    }
}

static void _arm_undo_inject(void* arg)
{
    trampoline_arm64_t* handle = arg;

    size_t copy_size = (handle->redirect_opcode[2] != 0 ? 3 : 1) * sizeof(uint32_t);
    memcpy(handle->addr_target, handle->backup_opcode, copy_size);
}

static int _arm64_inline_hook_inject(void** origin, void* target, void* detour)
{
    uint32_t jump_code[3] = { 0, 0, 0 };
    _arm_fill_jump_code(jump_code, target, detour);

    trampoline_arm64_t* handle = calloc(1, sizeof(trampoline_arm64_t) + sizeof(uint32_t) * (3 * 2));
    if (handle == NULL)
    {
        goto err;
    }
    _arm_init_trampoline(handle, jump_code, target, detour);

    if (_modify_opcode(target, jump_code[2] != 0 ? 3 : 1, _arm_do_inject, handle) < 0)
    {
        free(handle);
        goto err;
    }

    _reflash_insn_cache();
    *origin = handle->wrap_opcode;

    return 0;

err:
    *origin = NULL;
    return -1;
}


static void _arm64_inline_hook_uninject(void** origin)
{
    trampoline_arm64_t* handle = container_of(*origin, trampoline_arm64_t, wrap_opcode);

    if (_modify_opcode(handle->addr_target, handle->redirect_opcode[2] != 0 ? 3 : 1, _arm_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }

    * origin = NULL;
}

INLINE_HOOK_DECLARE_INTERFACE(_arm64_inline_hook_inject, _arm64_inline_hook_uninject)

#else
#   error "unsupport hardware platform"
#endif
