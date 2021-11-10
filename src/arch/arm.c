#include "arch/arm.h"
#include "os/os.h"
#include <inttypes.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

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
    assert((uintptr_t)dest < (uintptr_t)0xffffffff);
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

static size_t _arm_get_opcode_size(const arm_trampoline_t* handle)
{
	return handle->redirect_opcode[sizeof(handle->redirect_opcode) - 1] == 0 ? 1 : 2;
}

static void _arm_do_inject(void* arg)
{
    arm_trampoline_t* handle = arg;

    size_t copy_size = _arm_get_opcode_size(handle) * sizeof(uint32_t);
    memcpy(handle->addr_target, handle->redirect_opcode, copy_size);
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
    uint32_t insn = handle->addr_target[ctx->i_offset];
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

int uhook_arm_inject(void** token, void** fn_call, void* target, void* detour)
{
    arm_trampoline_t* handle = _alloc_execute_memory(sizeof(arm_trampoline_t));
    if (handle == NULL)
    {
        return -1;
    }
    _arm_init_trampoline(handle, target, detour);

    if (_system_modify_opcode(target, handle->redirect_opcode[2] != 0 ? 3 : 1, _arm_do_inject, handle) < 0)
    {
        _free_execute_memory(handle);
        return -1;
    }

    *token = handle;
    *fn_call = handle->wrap_opcode;
    _flush_instruction_cache(target, sizeof(handle->redirect_opcode));

    return 0;
}

void uhook_arm_uninject(void* token)
{
    arm_trampoline_t* handle = token;
    if (_system_modify_opcode(handle->addr_target, handle->redirect_opcode[2] != 0 ? 3 : 1, _arm_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }
    _flush_instruction_cache(handle->addr_target, sizeof(handle->redirect_opcode));
    _free_execute_memory(handle);
}
