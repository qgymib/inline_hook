#include "uhook.h"
#include "arch/x86_64.h"
#include "os/os.h"
#include "os/elf.h"
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <Zydis/Zydis.h>

#define INLINE_HOOK_DEBUG
#include "log.h"

#define X86_64_MAX_INSTRUCTION_SIZE         15
#define X86_64_OPCODE_SIZE_JUMP_SHORT       2
#define X86_64_OPCODE_SIZE_JUMP_NEAR        5
#define X86_64_OPCODE_SIZE_JUMP_FAR         14
#define X86_64_OPCODE_INT3                  (0xcc)

/**
 * @brief List of conditional jump instructions
 */
#define X86_64_JCC_MAP(xx) \
    xx(ZYDIS_MNEMONIC_JB)    \
    xx(ZYDIS_MNEMONIC_JBE)   \
    xx(ZYDIS_MNEMONIC_JCXZ)  \
    xx(ZYDIS_MNEMONIC_JECXZ) \
    xx(ZYDIS_MNEMONIC_JKNZD) \
    xx(ZYDIS_MNEMONIC_JKZD)  \
    xx(ZYDIS_MNEMONIC_JL)    \
    xx(ZYDIS_MNEMONIC_JLE)   \
    xx(ZYDIS_MNEMONIC_JNB)   \
    xx(ZYDIS_MNEMONIC_JNBE)  \
    xx(ZYDIS_MNEMONIC_JNL)   \
    xx(ZYDIS_MNEMONIC_JNLE)  \
    xx(ZYDIS_MNEMONIC_JNO)   \
    xx(ZYDIS_MNEMONIC_JNP)   \
    xx(ZYDIS_MNEMONIC_JNS)   \
    xx(ZYDIS_MNEMONIC_JNZ)   \
    xx(ZYDIS_MNEMONIC_JO)    \
    xx(ZYDIS_MNEMONIC_JP)    \
    xx(ZYDIS_MNEMONIC_JRCXZ) \
    xx(ZYDIS_MNEMONIC_JS)    \
    xx(ZYDIS_MNEMONIC_JZ)

 /**
  * @brief List of unconditional jump instructions
  */
#define X86_64_JMP_MAP(xx)  \
    xx(ZYDIS_MNEMONIC_JMP)

  /**
   * @brief List of call instructions
   */
#define X86_64_CALL_MAP(xx) \
    xx(ZYDIS_MNEMONIC_CALL)

   /**
    * @brief List of relative address instructions
    */
#define X86_64_REL_INSN_MAP(xx)   \
    X86_64_JCC_MAP(xx)  \
    X86_64_JMP_MAP(xx)  \
    X86_64_CALL_MAP(xx)

typedef struct x86_64_patch_ctx
{
    size_t      pos_insn;               /**< The insn current decode */
}x86_64_patch_ctx_t;
#define X86_64_PATCH_CTX_INIT { 0 }

/**
 * @see https://www.felixcloutier.com/x86/
 */
typedef struct x86_64_trampoline
{
    uint8_t*    addr_target;                                    /**< Target function address */
    uint8_t*    addr_detour;                                    /**< Detour function address */
    size_t      size_target;                                    /**< Function size of target */

    size_t      redirect_size;                                  /**< Size of redirect code */
    uint8_t     redirect_opcode[X86_64_OPCODE_SIZE_JUMP_FAR];   /**< Opcode to redirect to detour function */
    uint8_t     backup_opcode[X86_64_OPCODE_SIZE_JUMP_FAR];     /**< Original function code for recover inject */

    size_t      trampoline_cap;                                 /**< The capacity of trampoline */
    size_t      trampoline_size;                                /**< The size of trampoline */
    uint8_t     trampoline[];                                   /**< Trampoline */
}x86_64_trampoline_t;

static int _x86_64_is_8bit_size(ptrdiff_t addr_diff)
{
    return -128 <= addr_diff && addr_diff <= 127;
}

static int _x86_64_is_16bit_size(ptrdiff_t addr_diff)
{
    return -32768 <= addr_diff && addr_diff <= 32767;
}

static int _x86_64_is_32bit_size(ptrdiff_t addr_diff)
{
    return -(ptrdiff_t)2147483648 <= addr_diff && addr_diff <= (ptrdiff_t)2147483647;
}

static int _x86_64_fill_jump_code_short(uint8_t jump_code[], size_t size, ptrdiff_t addr_diff)
{
    if (size < X86_64_OPCODE_SIZE_JUMP_SHORT)
    {
        return -1;
    }

    jump_code[0] = 0xeb;
    jump_code[1] = addr_diff - X86_64_OPCODE_SIZE_JUMP_SHORT;

    return X86_64_OPCODE_SIZE_JUMP_SHORT;
}

/**
 * ```
 * e9 4_byte_rel_addr
 * ```
 */
static int _x86_64_fill_jump_code_near(uint8_t jump_code[], size_t size, ptrdiff_t addr_diff)
{
    assert(_x86_64_is_32bit_size(addr_diff));
    if (size < X86_64_OPCODE_SIZE_JUMP_NEAR)
    {
        return -1;
    }

    jump_code[0] = 0xE9;
    uint32_t code = (uint32_t)(addr_diff - X86_64_OPCODE_SIZE_JUMP_NEAR);
    memcpy(&jump_code[1], &code, sizeof(code));

    return X86_64_OPCODE_SIZE_JUMP_NEAR;
}

/**
 * ```
 * ff 25 00 00 00 00           jmp qword ptr [rip]      jmp *(%rip)
 * yo ur ad dr re ss he re     some random assembly
 * ```
 */
static int _x86_64_fill_jump_code_far(uint8_t jump_code[], size_t size, void* dst_addr)
{
    if (size < X86_64_OPCODE_SIZE_JUMP_FAR)
    {
        return -1;
    }

    jump_code[0] = 0xff;
    jump_code[1] = 0x25;
    jump_code[2] = 0x00;
    jump_code[3] = 0x00;
    jump_code[4] = 0x00;
    jump_code[5] = 0x00;
    uint64_t code = (uint64_t)(dst_addr);
    memcpy(&jump_code[6], &code, sizeof(code));
    return X86_64_OPCODE_SIZE_JUMP_FAR;
}

/**
 * @param[in] buffer    Buffer to fill jump code
 * @param[in] size      Buffer size
 * @param[in] src_addr  Address of jump code
 * @param[in] dst_addr  Address of destination
 * @return              How many bytes written, or -1 if failure.
 */
static int _x86_64_fill_jump_code(uint8_t buffer[], size_t size, void* src_addr, void* dst_addr)
{
    ptrdiff_t addr_diff = (uint8_t*)dst_addr - (uint8_t*)src_addr;

    if (_x86_64_is_8bit_size(addr_diff))
    {
        return _x86_64_fill_jump_code_short(buffer, size, addr_diff);
    }
    if (_x86_64_is_32bit_size(addr_diff))
    {
        return _x86_64_fill_jump_code_near(buffer, size, addr_diff);
    }

    return _x86_64_fill_jump_code_far(buffer, size, dst_addr);
}

static void _x86_64_do_inject(void* arg)
{
    x86_64_trampoline_t* handle = arg;
    memcpy(handle->addr_target, handle->redirect_opcode, handle->redirect_size);
}

static void _x86_64_undo_inject(void* arg)
{
    x86_64_trampoline_t* handle = arg;
    memcpy(handle->addr_target, handle->backup_opcode, handle->redirect_size);
}

static ZydisAddressWidth _x86_64_get_address_width(void)
{
    switch (sizeof(void*))
    {
    case 2:
        return ZYDIS_ADDRESS_WIDTH_16;
    case 4:
        return ZYDIS_ADDRESS_WIDTH_32;
    case 8:
        return ZYDIS_ADDRESS_WIDTH_64;
    default:
        break;
    }
    return ZYDIS_ADDRESS_WIDTH_MAX_VALUE;
}

static ZydisMachineMode _x86_64_get_machine_mode(void)
{
    switch (sizeof(void*))
    {
    case 4:
        return ZYDIS_MACHINE_MODE_LEGACY_32;
    case 8:
        return ZYDIS_MACHINE_MODE_LONG_64;
    default:
        return ZYDIS_MACHINE_MODE_MAX_VALUE;
    }
}

static unsigned _x86_64_calc_mini_addr_width(ptrdiff_t addr_diff)
{
    if (_x86_64_is_8bit_size(addr_diff))
    {
        return 8;
    }
    if (_x86_64_is_16bit_size(addr_diff))
    {
        return 16;
    }
    if (_x86_64_is_32bit_size(addr_diff))
    {
        return 32;
    }
    return 64;
}

static int _86_64_overwrite_jmp_operand(x86_64_trampoline_t* handle, x86_64_patch_ctx_t* patch, const ZydisDecodedInstruction* insn, ptrdiff_t addr_diff)
{
    size_t imm_offset = insn->raw.imm[0].offset;
    switch (insn->operands[0].size)
    {
    case 8:
        handle->trampoline[patch->pos_insn + imm_offset] = (uint8_t)addr_diff;
        return 1;
    case 16:
    {
        uint16_t code = (uint16_t)addr_diff;
        memcpy(&handle->trampoline[patch->pos_insn + imm_offset], &code, sizeof(code));
        return 1;
    }
    case 32:
    {
        uint32_t code = (uint32_t)addr_diff;
        memcpy(&handle->trampoline[patch->pos_insn + imm_offset], &code, sizeof(code));
        return 1;
    }
    default:
        LOG("unknown operand size(%u)", (unsigned)insn->operands[0].size);
        return -1;
    }
}

/**
 * @see https://www.felixcloutier.com/x86/jcc
 */
static int _x86_64_fix_jcc(x86_64_trampoline_t* handle, x86_64_patch_ctx_t* patch,
    const ZydisDecodedInstruction* insn)
{
    /* Calculate destination address */
    ZyanU64 dst_addr;
    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(insn, &insn->operands[0],
        (ZyanU64)&handle->addr_target[patch->pos_insn], &dst_addr)))
    {
        return -1;
    }

    const int b_dst_is_in_body = (uintptr_t)handle->addr_target <= dst_addr
        && dst_addr <= (uintptr_t)handle->addr_target + handle->size_target;

    /* In most case, jcc destination should inside function body */
    if (b_dst_is_in_body)
    {
        return 0;
    }

    /*
     * jcc have three type of operand: rel8 / rel16 / rel32.
     * We must keep instruction width unchanged.
     */
    ptrdiff_t addr_diff = dst_addr - (uintptr_t)&handle->trampoline[patch->pos_insn];
    unsigned mini_rel_width = _x86_64_calc_mini_addr_width(addr_diff);

    /* If original operand width is large enough, just modify it */
    if (mini_rel_width <= insn->operands[0].size)
    {
        return _86_64_overwrite_jmp_operand(handle, patch, insn, addr_diff);
    }

    /* If operand width is not enough, we need to build a forward instruction */
    ptrdiff_t fi_diff = &handle->trampoline[handle->trampoline_size] - &handle->trampoline[patch->pos_insn];
    /* If we cannot jump to forward instruction, then no magic can be done. */
    if (_x86_64_calc_mini_addr_width(fi_diff) > insn->operands[0].size)
    {
        LOG("too far away from forward instruction: distance is %ld byte(s) but operand only has %u bit",
            (long)fi_diff, (unsigned)insn->operands[0].size);
        return -1;
    }

    /* Build forward instruction */
    int written_size = _x86_64_fill_jump_code(&handle->trampoline[handle->trampoline_size],
        handle->trampoline_cap - handle->trampoline_size, &handle->trampoline[handle->trampoline_size], (void*)dst_addr);
    if (written_size < 0)
    {
        return -1;
    }
    handle->trampoline_size += written_size;

    return _86_64_overwrite_jmp_operand(handle, patch, insn, fi_diff);
}

/**
 * @see https://www.felixcloutier.com/x86/jmp
 */
static int _x86_64_fix_jmp(x86_64_trampoline_t* handle, x86_64_patch_ctx_t* patch,
    const ZydisDecodedInstruction* insn)
{
    /**
     * For now I have no idea how to fix ModRM:r/m (r), so it is better to leave it alone.
     */
    if (insn->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
        || insn->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
        || insn->operands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
        return 0;
    }

    return _x86_64_fix_jcc(handle, patch, insn);
}

/**
 * @see https://www.felixcloutier.com/x86/call
 */
static int _x86_64_fix_call(x86_64_trampoline_t* handle, x86_64_patch_ctx_t* patch,
    const ZydisDecodedInstruction* insn)
{
    /**
     * For now I have no idea how to fix ModRM:r/m (r), so it is better to leave it alone.
     */
    if (insn->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
        || insn->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
        || insn->operands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
        return 0;
    }

    return _x86_64_fix_jcc(handle, patch, insn);
}

/**
 * we only need to fix relative address that outside original function body.
 * @return  0 if do nothing; 1 if patch success; -1 if patch failure
 */
static int _x86_64_patch_instruction(x86_64_trampoline_t* handle, x86_64_patch_ctx_t* patch,
    const ZydisDecodedInstruction* insn)
{
#define X86_64_PATCH_JCC(xx)    \
    case xx: return _x86_64_fix_jcc(handle, patch, insn);

#define X86_64_PATCH_JMP(xx)    \
    case xx: return _x86_64_fix_jmp(handle, patch, insn);

#define X86_64_PATCH_CALL(xx)   \
    case xx: return _x86_64_fix_call(handle, patch, insn);

    switch (insn->mnemonic)
    {
        X86_64_JCC_MAP(X86_64_PATCH_JCC)
            X86_64_JMP_MAP(X86_64_PATCH_JMP)
            X86_64_CALL_MAP(X86_64_PATCH_CALL)
    default:    return 0;
    }

#undef X86_64_PATCH_CALL
#undef X86_64_PATCH_JMP
#undef X86_64_PATCH_JCC
}

/**
 * @brief Generate swap code and jump to original function
 * @return  If return size if smaller than `num_opcode`, it is failure
 */
static int _x86_64_generate_trampoline_opcode(x86_64_trampoline_t* handle)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, _x86_64_get_machine_mode(), _x86_64_get_address_width());
    ZydisDecodedInstruction instruction;

    x86_64_patch_ctx_t patch = X86_64_PATCH_CTX_INIT;
    for (patch.pos_insn = 0;
        ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, handle->trampoline + patch.pos_insn, handle->size_target - patch.pos_insn, &instruction));
        patch.pos_insn += instruction.length)
    {
        switch (_x86_64_patch_instruction(handle, &patch, &instruction))
        {
        case 0:     break;
        case 1:     break;
        default:    return -1;
        }
    }

    return 0;
}

/**
 * @return bool
 */
static int _x86_64_is_jump_insn(ZydisMnemonic insn)
{
#define X86_64_EXPLAIN_JCC_MAP(x) \
    case x: return 1;

    switch (insn)
    {
        X86_64_REL_INSN_MAP(X86_64_EXPLAIN_JCC_MAP)
    default:    return 0;
    }

#undef X86_64_EXPLAIN_JCC_MAP
}

static size_t _x86_64_calc_trampoline_size(const void* func, size_t func_size)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, _x86_64_get_machine_mode(), _x86_64_get_address_width());
    ZydisDecodedInstruction instruction;

    /* calculate `jmp` number */
    size_t pos;
    size_t jmp_cnt = 0;
    for (pos = 0;
        ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (uint8_t*)func + pos, func_size - pos, &instruction));
        pos += instruction.length)
    {
        if (_x86_64_is_jump_insn(instruction.mnemonic))
        {
            jmp_cnt++;
        }
    }

    /* The worst case we need every one wrap to far jump */
    size_t jmp_far_size = X86_64_OPCODE_SIZE_JUMP_FAR * jmp_cnt;

    return func_size + jmp_far_size;
}

int uhook_x86_64_inject(void** token, void** fn_call, void* target, void* detour)
{
    int ret;
    size_t target_func_size = elf_get_function_size(target);
    if (target_func_size == (size_t)-1)
    {
        return UHOOK_NOFUNCSIZE;
    }

    size_t trampoline_size = _x86_64_calc_trampoline_size(target, target_func_size);
    size_t malloc_size = ALIGN_SIZE(sizeof(x86_64_trampoline_t) + trampoline_size, _get_page_size());

    x86_64_trampoline_t* handle = _alloc_execute_memory(malloc_size);
    if (handle == NULL)
    {
        LOG("alloc execute memory with size(%zu) failed", malloc_size);
        return UHOOK_NOMEM;
    }
    memset(handle, X86_64_OPCODE_INT3, malloc_size);

    handle->addr_target = target;
    handle->addr_detour = detour;
    handle->size_target = target_func_size;
    handle->trampoline_cap = malloc_size - sizeof(x86_64_trampoline_t);

    if ((ret = _x86_64_fill_jump_code(handle->redirect_opcode,
        sizeof(handle->redirect_opcode), target, detour)) < 0)
    {
        LOG("generate redirect opcode failed");
        _free_execute_memory(handle);
        return UHOOK_UNKNOWN;
    }
    if ((size_t)ret > target_func_size)
    {
        LOG("target(%p) size is too small, need(%zu) actual(%zu)", target, (size_t)ret, target_func_size);
        _free_execute_memory(handle);
        return UHOOK_SMALLFUNC;
    }

    handle->redirect_size = ret;
    memcpy(handle->backup_opcode, target, ret);
    memcpy(handle->trampoline, target, target_func_size);
    handle->trampoline_size = target_func_size;

    if (_x86_64_generate_trampoline_opcode(handle) < 0)
    {
        _free_execute_memory(handle);
        return UHOOK_UNKNOWN;
    }

    if (_system_modify_opcode(target, handle->redirect_size, _x86_64_do_inject, handle) < 0)
    {
        _free_execute_memory(handle);
        return -1;
    }

    _flush_instruction_cache(target, handle->redirect_size);
    *token = handle;
    *fn_call = handle->trampoline;

    return UHOOK_SUCCESS;
}

void uhook_x86_64_uninject(void* token)
{
    x86_64_trampoline_t* handle = token;

    if (_system_modify_opcode(handle->addr_target, handle->redirect_size, _x86_64_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }
    _flush_instruction_cache(handle->addr_target, handle->redirect_size);
    _free_execute_memory(handle);
}
