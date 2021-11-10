#include "inlinehook.h"
#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include "once.h"
#include "elfparser.h"

#if defined(_WIN32)
#   include <windows.h>
#else
#   include <stdint.h>
#   include <unistd.h>
#   include <sys/mman.h>
#endif

#define INLINE_HOOK_DEBUG
#include "log.h"

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

/**
 * @brief align `size` to `align`
 */
#define ALIGN_SIZE(size, align) \
    (((uintptr_t)(size) + ((uintptr_t)(align) - 1)) & ~((uintptr_t)(align) - 1))

#define INLINE_HOOK_MAKE_INTERFACE(fn_inject, fn_uninject) \
    int inline_hook_inject(void** origin, void* target, void* detour) {\
        int ret;\
        if ((ret = fn_inject(origin, target, detour)) != 0) {\
            *origin = NULL;\
        }\
        return ret;\
    }\
    void inline_hook_uninject(void** origin) {\
        fn_uninject(*origin);\
        *origin = NULL;\
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

static int _unix_dl_iterate_phdr_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;

    uintptr_t* p_ret = data;
    *p_ret = info->dlpi_addr;

    return 1;
}

static uintptr_t _unix_get_relocation(void)
{
    uintptr_t ret = 0;
    dl_iterate_phdr(_unix_dl_iterate_phdr_callback, &ret);
    return ret;
}

/**
 * @return ((size_t)-1) is failure, otherwise success.
 */
static size_t _get_function_size(const void* addr)
{
    size_t ret = (size_t)-1;
    elf_symbol_t* symbol_list = NULL;
    FILE* f_exe = fopen("/proc/self/exe", "rb");
    uintptr_t relocation = _unix_get_relocation();
    uintptr_t target_addr = (uintptr_t)addr - relocation;

    elf_info_t* info = NULL;
    if (elf_parser_file(&info, f_exe)  != 0)
    {
        ret = (size_t)-1;
        goto fin;
    }

    size_t idx;
    for (idx = 0; idx < info->ehdr.e_shnum; idx++)
    {
        if (info->shdr[idx].sh_type == 0x02 || info->shdr[idx].sh_type == 0x0b)
        {
            int num = elf_parser_symbol(&symbol_list, info, idx);

            int i;
            for (i = 0; i < num; i++)
            {
                if (symbol_list[i].st_value == target_addr)
                {
                    ret = symbol_list[i].st_size;
                    goto fin;
                }
            }

            elf_release_symbol(symbol_list);
            symbol_list = NULL;
        }
    }

fin:
    if (symbol_list != NULL)
    {
        elf_release_symbol(symbol_list);
        symbol_list = NULL;
    }
    if (info != NULL)
    {
        elf_release_info(info);
        info = NULL;
    }
    fclose(f_exe);

    return ret;
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

/**
 * @brief Set memory protect mode as READ/WRITE/EXEC
 */
static int _system_protect_as_RWE(void* addr, size_t size)
{
    int flag_failure = 0;
#if defined(_WIN32)
    DWORD lpflOldProtect;
    flag_failure = 0 == VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#else
    flag_failure = 1;
#endif
    return flag_failure ? -1 : 0;
}

/**
 * @brief Set memory protect mode as READ/EXEC
 */
static int _system_protect_as_RE(void* addr, size_t size)
{
    int flag_failure = 0;
#if defined(_WIN32)
    DWORD lpflOldProtect;
    flag_failure = 0 == VirtualProtect(addr, size, PAGE_EXECUTE_READ, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(addr, size, PROT_READ | PROT_EXEC);
#else
    flag_failure = 1;
#endif
    return flag_failure ? -1 : 0;
}

static int _system_modify_opcode(void* addr, size_t size, void (*callback)(void*), void* data)
{
    const size_t page_size = _get_page_size();

    uint8_t* start_addr = (uint8_t*)_page_of(addr, page_size);
    uint8_t* end_addr = (uint8_t*)addr + size;

    const size_t n_page = ((end_addr - start_addr - 1) / page_size) + 1;
    const size_t protect_size = page_size * n_page;

    /* Remove write protect */
    if (_system_protect_as_RWE(start_addr, protect_size) < 0)
    {
        return -1;
    }

    /* call callback */
    callback(data);

    /* Add write protect */
    int ret = _system_protect_as_RE(start_addr, protect_size);
    assert(ret == 0); (void)ret;

    return 0;
}

/**
 * @brief Flush the processor's instruction cache for the region of memory.
 *
 * Some targets require that the instruction cache be flushed, after modifying
 * memory containing code, in order to obtain deterministic behavior.
 * 
 * @param[in] addr      Start address
 * @param[in] size      Address length
 */
static void _flush_instruction_cache(void* addr, size_t size)
{
#if defined(_WIN32)
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (process_handle == NULL)
    {
        return;
    }

    FlushInstructionCache(process_handle, addr, size);
    CloseHandle(process_handle);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache(addr, (uint8_t*)addr + size);
#else
#   error "unsupport flush_instruction_cache"
#endif
}

/**
 * @brief Alloc a block of memory that has EXEC attribute
 * @param[in] size  Memory size
 * @return          Address
 */
static void* _alloc_execute_memory(size_t size)
{
#if defined(_WIN32)
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    void* ptr = NULL;
    if (posix_memalign(&ptr, _get_page_size(), size) != 0)
    {
        return NULL;
    }
    if (_system_protect_as_RWE(ptr, size) < 0)
    {
        free(ptr);
        return NULL;
    }

    return ptr;
#endif
}

/**
 * @brief Release memory alloc by #_alloc_execute_memory()
 */
static void _free_execute_memory(void* ptr)
{
#if defined(_WIN32)
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    free(ptr);
#endif
}

#if defined(__i386__) || defined(__amd64__) || defined(_M_IX86) || defined(_M_AMD64)

#include "Zydis/Zydis.h"

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

static int _x86_64_inline_hook_inject(void** origin, void* target, void* detour)
{
    int ret;
    size_t target_func_size = _get_function_size(target);
    if (target_func_size == (size_t)-1)
    {
        return INLINK_HOOK_NOFUNCSIZE;
    }

    size_t trampoline_size = _x86_64_calc_trampoline_size(target, target_func_size);
    size_t malloc_size = ALIGN_SIZE(sizeof(x86_64_trampoline_t) + trampoline_size, _get_page_size());

    x86_64_trampoline_t* handle = _alloc_execute_memory(malloc_size);
    if (handle == NULL)
    {
        LOG("alloc execute memory with size(%zu) failed", malloc_size);
        return INLINK_HOOK_NOMEM;
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
        return INLINK_HOOK_UNKNOWN;
    }
    if ((size_t)ret > target_func_size)
    {
        LOG("target(%p) size is too small, need(%zu) actual(%zu)", target, (size_t)ret, target_func_size);
        _free_execute_memory(handle);
        return INLINK_HOOK_SMALLFUNC;
    }

    handle->redirect_size = ret;
    memcpy(handle->backup_opcode, target, ret);
    memcpy(handle->trampoline, target, target_func_size);
    handle->trampoline_size = target_func_size;

    if (_x86_64_generate_trampoline_opcode(handle) < 0)
    {
        _free_execute_memory(handle);
        return INLINK_HOOK_UNKNOWN;
    }

    if (_system_modify_opcode(target, sizeof(handle->redirect_opcode), _x86_64_do_inject, handle) < 0)
    {
        _free_execute_memory(handle);
        return -1;
    }

    *origin = handle->trampoline;
    _flush_instruction_cache(target, handle->redirect_size);

    return INLINK_HOOK_SUCCESS;
}

static void _x86_64_inline_hook_uninject(void* origin)
{
    x86_64_trampoline_t* handle = container_of(origin, x86_64_trampoline_t, trampoline);
    if (_system_modify_opcode(handle->addr_target, sizeof(handle->redirect_opcode), _x86_64_undo_inject, handle) > 0)
    {
        assert(!"modify opcode failed");
    }
    _flush_instruction_cache(handle->addr_target, handle->redirect_size);
    _free_execute_memory(handle);
}

INLINE_HOOK_MAKE_INTERFACE(_x86_64_inline_hook_inject, _x86_64_inline_hook_uninject)

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

static int _arm64_inline_hook_inject(void** origin, void* target, void* detour)
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

static void _arm64_inline_hook_uninject(void* origin)
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
