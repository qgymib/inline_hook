#include "uhook.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "once.h"

#include "os_elf.h"
#include "arch_x86_64.h"

#define INLINE_HOOK_DEBUG
#include "log.h"

#define UHOOK_ATTR_INLINE   1
#define UHOOK_ATTR_GOTPLT   2

#if defined(__i386__) || defined(__amd64__) || defined(_M_IX86) || defined(_M_AMD64)

int uhook_inject(uhook_token_t* token, void* target, void* detour)
{
    void* inject_token = NULL;
    void* inject_call = NULL;
    int ret = uhook_x86_64_inject(&inject_token, &inject_call, target, detour);
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
    int ret = elf_inject_got_patch(&inject_token, &inject_token, name, detour);

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
    if (token->attrs & UHOOK_ATTR_GOTPLT)
    {
        elf_inject_got_unpatch(token->token);
        goto fin;
    }

    if (token->attrs & UHOOK_ATTR_INLINE)
    {
        uhook_x86_64_uninject(token->token);
        goto fin;
    }

fin:
    memset(token, 0, sizeof(*token));
}

#elif defined(__arm__)

typedef struct arm_convert_ctx
{
    size_t i_offset;    /**< Instruction offset */
    size_t o_offset;    /**< Opcode offset */
    size_t ext_pos;     /**< EXT space position */
}arm_convert_ctx_t;
#define ARM_CONVERT_CTX_INIT    { 0, 0, 4 }

/**
 * @brief Hook context for arm64
 *
 * The jump code can be either 1 instruction (with address space < 32MB):
 * ```
 * b #(address)
 * ```
 * or 2 instructions (with any address space)
 * ```
 * ldr  pc, [pc, #-4]
 * .word    address
 * ```
 *
 * To know whether 12 bytes code is used, check if #trampoline_arm64_t::redirect_opcode[2]
 * is non-zero.
 */
typedef struct arm_trampoline
{
    uint32_t*   addr_target;            /**< Target function address */
    uint32_t*   addr_detour;            /**< Detour function address */
    uint32_t    redirect_opcode[2];     /**< Opcode to redirect to detour function */
    uint32_t    backup_opcode[2];       /**< Original function code */

    /**
     * @brief Opcode to call original function, 32 bytes.
     * 
     * Instruction layout:
     * ```
     *  [LOW ADDR] | ------------------------ |
     *           0 |                          |
     *           n | wrap original code       | -> max 2 instructions
     *             | ------------------------ |
     *         n+1 |                          |
     *         n+2 | force redirect code      | -> max 2 instructions
     *             | ------------------------ |
     *       [gap] | 0x00                     | -> Any space left must set to 0x00
     *             | ------------------------ |
     *           4 |                          |
     *             | ext space (0x00)         | -> EXT space for wrapping opcode
     *           7 |                          |
     * [HIGH ADDR] | ------------------------ |
     * ```
     * 
     * The wrap instruction is a little bit complex if original one is a relative branch Instructions:
     * b label:     b [EXT], ldr pc, =address
     * bl label:    bl [EXT], ldr pc, =address
     * blx label:   blx [EXT], ldr pc, =address
     */
    uint32_t    wrap_opcode[8];         /**< Opcode to call original function */
}arm_trampoline_t;

static int _arm_fill_jump_code_near(uint32_t jump_code[1], intptr_t addr_diff)
{
    jump_code[0] = (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0xea000000;
    return 1;
}

static int _arm_fill_jump_code_far(uint32_t jump_code[2], void* dest)
{
    assert(dest < 0xffffffff);
    jump_code[0] = 0xe51ff004;
    jump_code[1] = (uint32_t)dest;
    return 2;
}

/**
 * @brief Generate jump code
 * @param[out] jump_code    The generated jump code
 * @param[in] target        The position where code will be executed
 * @param[in] detour        The destination address
 */
static int _arm_fill_jump_code(uint32_t jump_code[2], void* target, void* detour)
{
    ptrdiff_t addr_diff = (uint8_t*)detour - (uint8_t*)target;
    if (-(ptrdiff_t)0x2000000 <= addr_diff && addr_diff < (ptrdiff_t)0x2000000)
    {
        return _arm_fill_jump_code_near(jump_code, addr_diff);
    }

    return _arm_fill_jump_code_far(jump_code, detour);
}

static void _arm_do_inject(void* arg)
{
    arm_trampoline_t* handle = arg;

    size_t copy_size = (handle->redirect_opcode[2] != 0 ? 3 : 1) * sizeof(uint32_t);
    memcpy(handle->addr_target, handle->redirect_opcode, copy_size);
}

static size_t _arm_get_opcode_size(const arm_trampoline_t* handle)
{
    return handle->redirect_opcode[sizeof(handle->redirect_opcode) - 1] == 0 ? 1 : 2;
}

/**
 * 
 * | opcode | encode algorithm                                   |
 * | ------ | -------------------------------------------------- |
 * | b      | (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0xea000000 |
 * | bl     | (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0xeb000000 |
 * | blx    | (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0xfa000000 |
 * | beq    | (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0x0a000000 |
 * | bne    | (((addr_diff - 8) >> 2) & 0x00FFFFFF) | 0x1a000000 |
 * 
 * @return  0: not convert; 1: success; -1: failure
 */
static int _arm_try_convert_branch_insn(arm_trampoline_t* handle, arm_convert_ctx_t* ctx)
{
    uin32_t insn = handle->addr_target[ctx->i_offset];
    switch (insn & 0xff000000)
    {
    case 0xea000000:    /* b */
    case 0xeb000000:    /* bl */
    case 0xfa000000:    /* blx */
    case 0x0a000000:    /* beq */
    case 0x1a000000:    /* bne */
    {
        ptrdiff_t addr_diff = (uint8_t*)&handle->wrap_opcode[ctx->ext_pos] - (uint8_t*)&handle->wrap_opcode[ctx->o_offset];
        handle->wrap_opcode[ctx->o_offset++] = (insn & 0xff000000) | (((uint32_t)(addr_diff - 8) >> 2) & 0x00ffffff);

        addr_diff = ((insn & 0x00ffffff) << 2) + 8;
        void* dst_addr = (uint8_t*)handle->addr_target + addr_diff;

        ctx->ext_pos += _arm_fill_jump_code_far(&handle->wrap_opcode[ctx->ext_pos], dst_addr);

        return 1;
    }
    default:
        break;
    }
    return 0;
}

static int _arm_generate_trampoline_opcode(arm_trampoline_t* handle)
{
    size_t max_check_size = _arm_get_opcode_size(handle);

    int ret;
    arm_convert_ctx_t convert_ctx = ARM_CONVERT_CTX_INIT;
    for (; convert_ctx.i_offset < max_check_size; convert_ctx.i_offset++)
    {
        /* bx lr */
        if (handle->addr_target[convert_ctx.i_offset] == 0xe12fff1e)
        {
            return -1;
        }

        ret = _arm_try_convert_branch_insn(handle, &convert_ctx);
        if (ret == -1)
        {
            return -1;
        }
        else if (ret == 1)
        {
            continue;
        }

        handle->wrap_opcode[convert_ctx.o_offset++] = handle->addr_target[convert_ctx.i_offset];
    }

    ret = _arm_fill_jump_code(&handle->wrap_opcode[convert_ctx.o_offset],
        &handle->wrap_opcode[convert_ctx.o_offset], &handle->addr_target[convert_ctx.i_offset]);
    convert_ctx.o_offset += ret;

    return 0;
}

static int _arm_init_trampoline(arm_trampoline_t* handle, void* target, void* detour)
{
    memset(handle, 0, sizeof(*handle));

    handle->addr_target = target;
    handle->addr_detour = detour;
    
    int ret = _arm_fill_jump_code(handle->redirect_opcode, target, detour);
    if (ret < 0)
    {
        return -1;
    }
    memcpy(handle->backup_opcode, target, ret);

    return _arm_generate_trampoline_opcode(handle);
}

static void _arm_undo_inject(void* arg)
{
    arm_trampoline_t* handle = arg;

    size_t copy_size = (handle->redirect_opcode[2] != 0 ? 3 : 1) * sizeof(uint32_t);
    memcpy(handle->addr_target, handle->backup_opcode, copy_size);
}

int uhook_inject(void** origin, void* target, void* detour)
{
    arm_trampoline_t* handle = _alloc_execute_memory(sizeof(arm_trampoline_t));
    if (handle == NULL)
    {
        return -1;
    }
    _arm_init_trampoline(handle, jump_code, target, detour);

    if (_system_modify_opcode(target, jump_code[2] != 0 ? 3 : 1, _arm_do_inject, handle) < 0)
    {
        _free_execute_memory(handle);
        return -1;
    }

    *origin = handle->wrap_opcode;
    _flush_instruction_cache(target, sizeof(handle->redirect_opcode));

    return 0;
}

void uhook_uninject(void* origin)
{
    arm_trampoline_t* handle = container_of(origin, arm_trampoline_t, wrap_opcode);
    if (_system_modify_opcode(handle->addr_target, handle->redirect_opcode[2] != 0 ? 3 : 1, _arm_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }
    _flush_instruction_cache(handle->addr_target, sizeof(handle->redirect_opcode));
    _free_execute_memory(handle);
}

INLINE_HOOK_MAKE_INTERFACE(_arm64_inline_hook_inject, _arm64_inline_hook_uninject)

#else
#   error "unsupport hardware platform"
INLINE_HOOK_MAKE_INTERFACE(NULL, NULL)
#endif
