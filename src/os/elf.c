#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "uhook.h"
#include "os/os.h"
#include "os/elfparser.h"
#include "os/elf.h"

#define INLINE_HOOK_DEBUG
#include "log.h"

#if defined(__arm__) || defined(_M_ARM)
#   define XH_ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#   define XH_ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#   define XH_ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__) || defined(_M_ARM64)
#   define XH_ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#   define XH_ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#   define XH_ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__) || defined(_M_IX86)
#   define XH_ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#   define XH_ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#   define XH_ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_AMD64)
#   define XH_ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#   define XH_ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#   define XH_ELF_R_GENERIC_ABS       R_X86_64_64
#else
#   error unknown arch
#endif

#if defined(__LP64__)
#   define XH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#   define XH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#   define XH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#   define XH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#define FOREACH_BLOCK(token, addr, size, width) \
    for (token = (uintptr_t)addr;\
        token < (uintptr_t)addr + (size_t)size;\
        token = (uintptr_t)token + (size_t)width)

typedef struct relocation_helper
{
    int             ret;
    void*           loc_addr;
    void*           symbol_addr;
}relocation_helper_t;

typedef struct dynamic_phdr
{
    ElfW(Dyn)*      dyn_phdr;       /**< Dynamic section address */
    size_t          dyn_phdr_size;  /**< Dynamic section size in bytes */

    const char*     strtab;         /**< .dynstr (string-table) */
    ElfW(Sym)*      symtab;         /**< .dynsym (symbol-index to string-table's offset) */
    int             is_rela;        /**< Rela / Rel */

    ElfW(Addr)      relplt;         /**< .rel.plt or .rela.plt */
    ElfW(Word)      relplt_sz;
    ElfW(Addr)      reldyn;         /**< .rel.dyn or .rela.dyn */
    ElfW(Word)      reldyn_sz;

    /* ELF Hash */
    uint32_t*       bucket;
    uint32_t        bucket_cnt;
    uint32_t*       chain;
    uint32_t        chain_cnt;      /**< invalid for GNU hash */

    /* GNU Hash */
    ElfW(Addr)*     bloom;          /**< Check this value for GNU Hash usage */
    size_t          symoffset;
    size_t          bloom_sz;
    size_t          bloom_shift;
}dynamic_phdr_t;

typedef struct inject_got_ctx
{
    const char*     name;           /**< Symbol name */
    void*           detour;         /**< Detour function address */
    void*           origin;         /**< Original function address */
    int             inject_ret;     /**< Inject result */

    size_t          symidx;         /**< Symbol index for PLT/GOT */
    char            elfpath[256];   /**< Symbol location */
    uintptr_t       relocation;     /**< Load location */

    size_t          page_size;      /**< Page size */

    struct
    {
        ElfW(Addr)  addr_relplt;    /**< Address of inject position .rel(a).plt */
        ElfW(Addr)  addr_reldyn;    /**< Address of inject position .rel(a).dyn */
    }inject_info;

    dynamic_phdr_t  phdr_info;      /**< Program header info */
}inject_got_ctx_t;

static ElfW(Dyn)* _unix_get_dyn_phdr(struct dl_phdr_info* info, size_t* size)
{
    size_t i;
    for (i = 0; i < info->dlpi_phnum; i++)
    {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
        {
            *size = info->dlpi_phdr[i].p_memsz;
            return (ElfW(Dyn)*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        }
    }

    return NULL;
}

static int _unix_parser_dyn_phdr(inject_got_ctx_t* dst, ElfW(Dyn)* dyn_phdr, size_t dyn_phdr_size)
{
    size_t cnt = dyn_phdr_size / sizeof(ElfW(Dyn));
    size_t i;
    for (i = 0; i < cnt; i++)
    {
        switch (dyn_phdr[i].d_tag)
        {
            /* end of program header */
        case DT_NULL:
            i = cnt;
            break;

        case DT_STRTAB:
            dst->phdr_info.strtab = (const char*)dyn_phdr[i].d_un.d_ptr;
            break;

        case DT_SYMTAB:
            dst->phdr_info.symtab = (ElfW(Sym)*)dyn_phdr[i].d_un.d_ptr;
            break;

        case DT_PLTREL:
            dst->phdr_info.is_rela = dyn_phdr[i].d_un.d_val == DT_RELA;
            break;

        case DT_JMPREL:
            dst->phdr_info.relplt = dyn_phdr[i].d_un.d_ptr;
            break;

        case DT_PLTRELSZ:
            dst->phdr_info.relplt_sz = dyn_phdr[i].d_un.d_val;
            break;

        case DT_REL:
        case DT_RELA:
            dst->phdr_info.reldyn = dyn_phdr[i].d_un.d_ptr;
            break;

        case DT_RELSZ:
        case DT_RELASZ:
            dst->phdr_info.reldyn_sz = dyn_phdr[i].d_un.d_val;
            break;

        case DT_GNU_HASH:
        {
            uint32_t* raw = (uint32_t*)dyn_phdr[i].d_un.d_ptr;
            dst->phdr_info.bucket_cnt = raw[0];
            dst->phdr_info.symoffset = raw[1];
            dst->phdr_info.bloom_sz = raw[2];
            dst->phdr_info.bloom_shift = raw[3];
            dst->phdr_info.bloom = (ElfW(Addr)*)(&raw[4]);
            dst->phdr_info.bucket = (uint32_t*)(&(dst->phdr_info.bloom[dst->phdr_info.bloom_sz]));
            dst->phdr_info.chain = (uint32_t*)(&(dst->phdr_info.bucket[dst->phdr_info.bucket_cnt]));
            break;
        }

        case DT_HASH:
        {
            /* ignore DT_HASH when ELF contains DT_GNU_HASH hash table */
            if (dst->phdr_info.bloom != NULL)
            {
                continue;
            }

            uint32_t* raw = (uint32_t*)dyn_phdr[i].d_un.d_ptr;
            dst->phdr_info.bucket_cnt = raw[0];
            dst->phdr_info.chain_cnt = raw[1];
            dst->phdr_info.bucket = &raw[2];
            dst->phdr_info.chain = &(dst->phdr_info.bucket[dst->phdr_info.bucket_cnt]);
            break;
        }

        default:
            break;
        }
    }

    return 0;
}

static uint32_t _elf_gnu_hash(const uint8_t* name)
{
    uint32_t h = 5381;

    while (*name != 0)
    {
        h += (h << 5) + *name++;
    }
    return h;
}

static int _elf_gnu_hash_lookup_def(inject_got_ctx_t* self, const char* symbol, size_t* symidx)
{
    uint32_t hash = _elf_gnu_hash((uint8_t*)symbol);

    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = self->phdr_info.bloom[(hash / elfclass_bits) % self->phdr_info.bloom_sz];
    size_t mask = 0
        | (size_t)1 << (hash % elfclass_bits)
        | (size_t)1 << ((hash >> self->phdr_info.bloom_shift) % elfclass_bits);

    //if at least one bit is not set, this symbol is surely missing
    if ((word & mask) != mask) return -1;

    //ignore STN_UNDEF
    uint32_t i = self->phdr_info.bucket[hash % self->phdr_info.bucket_cnt];
    if (i < self->phdr_info.symoffset)
    {
        return -1;
    }

    //loop through the chain
    while (1)
    {
        const char* symname = self->phdr_info.strtab + self->phdr_info.symtab[i].st_name;
        const uint32_t  symhash = self->phdr_info.chain[i - self->phdr_info.symoffset];

        if ((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname))
        {
            *symidx = i;
            //LOG("found %s at symidx: %zu (GNU_HASH DEF)", symbol, *symidx);
            return 0;
        }

        /* chain ends with an element with the lowest bit set to 1 */
        if (symhash & (uint32_t)1)
        {
            break;
        }

        i++;
    }

    return -1;
}

static int _elf_gnu_hash_lookup_undef(inject_got_ctx_t* self, const char* symbol, size_t* symidx)
{
    uint32_t i;

    for (i = 0; i < self->phdr_info.symoffset; i++)
    {
        const char* symname = self->phdr_info.strtab + self->phdr_info.symtab[i].st_name;
        if (0 == strcmp(symname, symbol))
        {
            *symidx = i;
            LOG("found %s at symidx: %zu (GNU_HASH UNDEF)", symbol, *symidx);
            return 0;
        }
    }
    return -1;
}

static int _unix_find_symidx_by_name_gnu_hash_lookup(inject_got_ctx_t* info, const char* symbol, size_t* symidx)
{
    if (0 == _elf_gnu_hash_lookup_def(info, symbol, symidx))
    {
        return 0;
    }
    if (0 == _elf_gnu_hash_lookup_undef(info, symbol, symidx))
    {
        return 0;
    }
    return -1;
}

//ELF hash func
static uint32_t _elf_hash(const uint8_t* name)
{
    uint32_t h = 0, g;

    while (*name)
    {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }

    return h;
}

static int _unix_find_symidx_by_name_hash_lookup(inject_got_ctx_t* info, const char* symbol, size_t* symidx)
{
    uint32_t    hash = _elf_hash((uint8_t*)symbol);
    const char* symbol_cur;
    uint32_t    i;

    for (i = info->phdr_info.bucket[hash % info->phdr_info.bucket_cnt];
        0 != i; i = info->phdr_info.chain[i])
    {
        symbol_cur = info->phdr_info.strtab + info->phdr_info.symtab[i].st_name;

        if (0 == strcmp(symbol, symbol_cur))
        {
            *symidx = i;
            LOG("found %s at symidx: %zu (ELF_HASH)", symbol, *symidx);
            return 0;
        }
    }

    return -1;
}

static int _unix_find_symidx_by_name(inject_got_ctx_t* info, const char* name, size_t* symidx)
{
    if (info->phdr_info.bloom != NULL)
    {
        return _unix_find_symidx_by_name_gnu_hash_lookup(info, name, symidx);
    }
    return _unix_find_symidx_by_name_hash_lookup(info, name, symidx);
}

static int _util_get_mem_protect(uintptr_t addr, size_t len, const char* pathname, unsigned int* prot)
{
    uintptr_t  start_addr = addr;
    uintptr_t  end_addr = addr + len;
    FILE* fp;
    char       line[512];
    uintptr_t  start, end;
    char       perm[5];
    int        load0 = 1;
    int        found_all = 0;

    *prot = 0;

    if (NULL == (fp = fopen("/proc/self/maps", "r"))) return -1;

    while (fgets(line, sizeof(line), fp))
    {
        if (NULL != pathname)
            if (NULL == strstr(line, pathname)) continue;

        if (sscanf(line, "%"PRIxPTR"-%"PRIxPTR" %4s ", &start, &end, perm) != 3) continue;

        if (perm[3] != 'p') continue;

        if (start_addr >= start && start_addr < end)
        {
            if (load0)
            {
                //first load segment
                if (perm[0] == 'r') *prot |= PROT_READ;
                if (perm[1] == 'w') *prot |= PROT_WRITE;
                if (perm[2] == 'x') *prot |= PROT_EXEC;
                load0 = 0;
            }
            else
            {
                //others
                if (perm[0] != 'r') *prot &= ~PROT_READ;
                if (perm[1] != 'w') *prot &= ~PROT_WRITE;
                if (perm[2] != 'x') *prot &= ~PROT_EXEC;
            }

            if (end_addr <= end)
            {
                found_all = 1;
                break; //finished
            }
            else
            {
                start_addr = end; //try to find the next load segment
            }
        }
    }

    fclose(fp);

    if (!found_all) return -1;

    return 0;
}

static int _util_get_addr_protect(uintptr_t addr, const char* pathname, unsigned int* prot)
{
    return _util_get_mem_protect(addr, sizeof(addr), pathname, prot);
}

static int _util_set_addr_protect(uintptr_t addr, unsigned int prot, size_t page_size)
{
    if (0 != mprotect(_page_of((void*)addr, page_size), page_size, (int)prot))
    {
        return -1;
    }

    return 0;
}

static int _elf_replace_function(inject_got_ctx_t* self, ElfW(Addr) addr, void* new_func, void** old_func)
{
    void* old_addr;
    unsigned int  old_prot = 0;
    unsigned int  need_prot = PROT_READ | PROT_WRITE;
    int           r;

    //already replaced?
    //here we assume that we always have read permission, is this a problem?
    if (*(void**)addr == new_func) return 0;

    //get old prot
    if (0 != (r = _util_get_addr_protect(addr, self->elfpath, &old_prot)))
    {
        LOG("get addr prot failed. ret: %d", r);
        return r;
    }

    if (old_prot != need_prot)
    {
        //set new prot
        if (0 != (r = _util_set_addr_protect(addr, need_prot, self->page_size)))
        {
            LOG("set addr prot failed. ret: %d", r);
            return r;
        }
    }

    //save old func
    old_addr = *(void**)addr;
    if (NULL != old_func) *old_func = old_addr;

    //replace func
    *(void**)addr = new_func; //segmentation fault sometimes

    if (old_prot != need_prot)
    {
        //restore the old prot
        if (0 != (r = _util_set_addr_protect(addr, old_prot, self->page_size)))
        {
            LOG("restore addr prot failed. ret: %d", r);
        }
    }

    //clear cache
    _flush_instruction_cache(_page_of((void*)addr, self->page_size), self->page_size);

    return 0;
}

/**
 * @brief Check whether symidx inside this rel(a) region
 * @param[in] rel_common    rel(a) region address
 * @param[in] symidx        Symbol index
 * @param[in] is_rela       region is typeof rela
 * @param[in] is_plt        region is PLT
 * @param[out] r_offset     Offset of symbol slot
 * @return                  bool
 */
static int _elf_check_symbol(void* rel_common, uint32_t symidx, int is_rela, int is_plt, ElfW(Addr)* r_offset)
{
    size_t r_info;
    if (is_rela)
    {
        ElfW(Rela)*  rela = (ElfW(Rela)*)rel_common;
        r_info = rela->r_info;
        *r_offset = rela->r_offset;
    }
    else
    {
        ElfW(Rel)*  rel = (ElfW(Rel)*)rel_common;
        r_info = rel->r_info;
        *r_offset = rel->r_offset;
    }

    //check sym
    size_t r_sym = XH_ELF_R_SYM(r_info);
    if (r_sym != symidx)
    {
        return 0;
    }

    //check type
    size_t r_type = XH_ELF_R_TYPE(r_info);
    if (is_plt && r_type != XH_ELF_R_GENERIC_JUMP_SLOT)
    {
        return 0;
    }

    if (!is_plt && (r_type != XH_ELF_R_GENERIC_GLOB_DAT && r_type != XH_ELF_R_GENERIC_ABS))
    {
        return 0;
    }

    return 1;
}

static int _elf_find_and_replace_func(inject_got_ctx_t* self,
    int is_plt, void* new_func, void** old_func,
    uint32_t symidx, void* rel_common, int* found)
{
    ElfW(Addr)      r_offset;
    ElfW(Addr)      addr;
    int             r;

    if (NULL != found) *found = 0;

    if (!_elf_check_symbol(rel_common, symidx, self->phdr_info.is_rela, is_plt, &r_offset))
    {
        return 0;
    }

    if (NULL != found) *found = 1;

    /* do replace */
    addr = self->relocation + r_offset;
    if (addr < self->relocation)
    {
        return UHOOK_UNKNOWN;
    }

    if (is_plt)
    {
        self->inject_info.addr_relplt = addr;
    }
    else
    {
        self->inject_info.addr_reldyn = addr;
    }

    if (0 != (r = _elf_replace_function(self, addr, new_func, old_func)))
    {
        return r;
    }

    return 0;
}

static int _elf_inject_plt_got(inject_got_ctx_t* helper)
{
    uintptr_t rel_common;
    int found;
    int r;

    size_t step_width = helper->phdr_info.is_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));

    //replace for .rel(a).plt
    if (0 != helper->phdr_info.relplt)
    {
        FOREACH_BLOCK(rel_common, helper->phdr_info.relplt, helper->phdr_info.relplt_sz, step_width)
        {
            if (0 != (r = _elf_find_and_replace_func(helper, 1,
                helper->detour, &helper->origin,
                helper->symidx, (void*)rel_common, &found)))
            {
                return r;
            }
            if (found) break;
        }
    }

    //replace for .rel(a).dyn
    if (0 != helper->phdr_info.reldyn)
    {
        FOREACH_BLOCK(rel_common, helper->phdr_info.reldyn, helper->phdr_info.reldyn_sz, step_width)
        {
            if (0 != (r = _elf_find_and_replace_func(helper, 0,
                helper->detour, &helper->origin,
                helper->symidx, (void*)rel_common, NULL)))
            {
                return r;
            }
        }
    }

    return 0;
}

static int _unix_dl_iterate_phdr_got(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;

    inject_got_ctx_t* helper = data;
    helper->relocation = info->dlpi_addr;
    snprintf(helper->elfpath, sizeof(helper->elfpath), "%s", info->dlpi_name);

    /* find PT_DYNAMIC phdr */
    helper->phdr_info.dyn_phdr = _unix_get_dyn_phdr(info, &helper->phdr_info.dyn_phdr_size);
    if (helper->phdr_info.dyn_phdr == NULL)
    {
        return 0;
    }
    //LOG("phdr_dyn location: %p in `%s`", helper->phdr_info.dyn_phdr, info->dlpi_name);

    /* Parser PT_DYNAMIC program header */
    _unix_parser_dyn_phdr(helper, helper->phdr_info.dyn_phdr, helper->phdr_info.dyn_phdr_size);

    if (_unix_find_symidx_by_name(helper, helper->name, &helper->symidx) < 0)
    {/* Not found, find next shared phdr */
        LOG("symbol(%s) not found in `%s`", helper->name, info->dlpi_name);
        return 0;
    }

    /* inject GOT/PLT */
    helper->inject_ret = _elf_inject_plt_got(helper);
    return 1;
}

static int _elf_dl_iterate_phdr_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;

    relocation_helper_t* helper = data;
    helper->loc_addr = (void*)info->dlpi_addr;

    size_t i;
    for (i = 0; i < info->dlpi_phnum; i++)
    {
        uintptr_t start_addr = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        uintptr_t end_addr = start_addr + info->dlpi_phdr[i].p_memsz;

        if(start_addr <= (uintptr_t)helper->symbol_addr
            && (uintptr_t)helper->symbol_addr <= end_addr)
        {
            helper->ret = 0;
            return 1;
        }
    }

    return 0;
}

static const char* _elf_get_phdy_name(ElfW(Word) type)
{
    switch (type)
    {
    case PT_NULL:           return "NULL";
    case PT_LOAD:           return "LOAD";
    case PT_DYNAMIC:        return "DYNAMIC";
    case PT_INTERP:         return "INTERP";
    case PT_NOTE:           return "NOTE";
    case PT_SHLIB:          return "SHLIB";
    case PT_PHDR:           return "PHDR";
    case PT_TLS:            return "TLS";
    case PT_NUM:            return "NUM";
    case PT_LOOS:           return "LOOS";
    case PT_GNU_EH_FRAME:   return "GNU_EH_FRAME";
    case PT_GNU_STACK:      return "GNU_STACK";
    case PT_GNU_RELRO:      return "GNU_RELRO";
    case PT_SUNWBSS:        return "SUNWBSS";
    case PT_SUNWSTACK:      return "SUNWSTACK";
    case PT_HISUNW:         return "HISUNW";
    case PT_LOPROC:         return "LOPROC";
    case PT_HIPROC:         return "HIPROC";
    default:                return "UNKNOWN";
    }
}

static const char* _elf_get_p_flags(uint32_t flags)
{
    switch (flags)
    {
    case PF_X:                  return "--X";
    case PF_W:                  return "-W-";
    case PF_R:                  return "R--";
    case PF_X | PF_W:           return "-WX";
    case PF_X | PF_R:           return "R-X";
    case PF_W | PF_R:           return "RW-";
    case PF_X | PF_W | PF_R:    return "RWX";
    default:                    return "   ";
    }
}

static const char* _elf_get_dynamic_section_name(uint64_t d_tag)
{
    switch (d_tag)
    {
    case DT_NULL:               return "NULL";
    case DT_NEEDED:             return "NEEDED";
    case DT_PLTRELSZ:           return "PLTRELSZ";
    case DT_PLTGOT:             return "PLTGOT";
    case DT_HASH:               return "HASH";
    case DT_STRTAB:             return "STRTAB";
    case DT_SYMTAB:             return "SYMTAB";
    case DT_RELA:               return "RELA";
    case DT_RELASZ:             return "RELASZ";
    case DT_RELAENT:            return "RELAENT";
    case DT_STRSZ:              return "STRSZ";
    case DT_SYMENT:             return "SYMENT";
    case DT_INIT:               return "INIT";
    case DT_FINI:               return "FINI";
    case DT_SONAME:             return "SONAME";
    case DT_RPATH:              return "RPATH";
    case DT_SYMBOLIC:           return "SYMBOLIC";
    case DT_REL:                return "REL";
    case DT_RELSZ:              return "RELSZ";
    case DT_RELENT:             return "RELENT";
    case DT_PLTREL:             return "PLTREL";
    case DT_DEBUG:              return "DEBUG";
    case DT_TEXTREL:            return "TEXTREL";
    case DT_JMPREL:             return "JMPREL";
    case DT_BIND_NOW:           return "BIND_NOW";
    case DT_INIT_ARRAY:         return "INIT_ARRAY";
    case DT_FINI_ARRAY:         return "FINI_ARRAY";
    case DT_INIT_ARRAYSZ:       return "INIT_ARRAYSZ";
    case DT_FINI_ARRAYSZ:       return "FINI_ARRAYSZ";
    case DT_RUNPATH:            return "RUNPATH";
    case DT_FLAGS:              return "FLAGS";
    case DT_PREINIT_ARRAY:      return "PREINIT_ARRAY";
    case DT_PREINIT_ARRAYSZ:    return "PREINIT_ARRAYSZ";
    case DT_SYMTAB_SHNDX:       return "SYMTAB_SHNDX";
    case DT_NUM:                return "NUM";
    case DT_LOOS:               return "LOOS";
    case DT_HIOS:               return "HIOS";
    case DT_LOPROC:             return "LOPROC";
    case DT_HIPROC:             return "HIPROC";
    case DT_PROCNUM:            return "PROCNUM";
    case DT_GNU_HASH:           return "GNU_HASH";
    case DT_VERSYM:             return "VERSYM";
    case DT_RELACOUNT:          return "RELACOUNT";
    case DT_RELCOUNT:           return "RELCOUNT";
    case DT_FLAGS_1:            return "FLAGS_1";
    case DT_VERDEF:             return "VERDEF";
    case DT_VERDEFNUM:          return "VERDEFNUM";
    case DT_VERNEED:            return "VERNEED";
    case DT_VERNEEDNUM:         return "VERNEEDNUM";
    default:                    return "UNKNOWN";
    }
}

static void _eld_dump_dynamic_phdr(ElfW(Dyn)* phdr, size_t size)
{
    int ptr_width = sizeof(void*) == 8 ? 16 : 8;

    size_t cnt = size / sizeof(ElfW(Dyn));
    size_t i;

    for (i = 0; i < cnt; i++)
    {
        printf("%-*s 0x%016" PRIx64 " 0x%0*" PRIxPTR "\n",
            15, _elf_get_dynamic_section_name(phdr[i].d_tag),
            phdr[i].d_tag,
            ptr_width, phdr[i].d_un.d_ptr);
    }
}

static int _elf_dump_phdr_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size; (void)data;

    const char* str_split = sizeof(void*) == 8 ?
        "--------------------------------------------------" : "----------------------------------";
    int ptr_size = sizeof(void*) == 8 ? 16 : 8;

    printf("%s\n", str_split);
    printf("name: %s\n"
        "relocate: 0x%" PRIxPTR "\n",
        info->dlpi_name,
        info->dlpi_addr);

    printf("%-*s %-*s %-*s %-*s %-*s\n",
        12, "[PHDR:TYPE]",
        ptr_size + 2, "[VADDR]",
        ptr_size + 2, "[PADDR]",
        ptr_size + 2, "[MEMSZ]",
        ptr_size + 2, "[FLAGS]");

    size_t i;
    for (i = 0; i < info->dlpi_phnum; i++)
    {
        printf("%-*s 0x%0*" PRIxPTR " 0x%0*" PRIxPTR " 0x%0*zx %s\n",
            12, _elf_get_phdy_name(info->dlpi_phdr[i].p_type),
            ptr_size, (uintptr_t)info->dlpi_phdr[i].p_vaddr,
            ptr_size, (uintptr_t)info->dlpi_phdr[i].p_paddr,
            ptr_size, (size_t)info->dlpi_phdr[i].p_memsz,
            _elf_get_p_flags(info->dlpi_phdr[i].p_flags));
    }

    size_t dy_size;
    ElfW(Dyn)* dyn_phdr = _unix_get_dyn_phdr(info, &dy_size);
    if (dyn_phdr == NULL)
    {
        return 0;
    }

	printf("%-*s %-*s [VALUE]\n", 15, "[DYN:TAG]", 18, "[TAG:HEX]");
    _eld_dump_dynamic_phdr(dyn_phdr, dy_size);

    printf("%s\n", str_split);
    return 0;
}

/**
 * @return a string need to free
 */
static int _elf_find_path(uintptr_t addr, char* buffer, size_t size)
{
    int ret = -1;
    char perm[5];
    uintptr_t base_addr, end_addr;
    unsigned long offset;
    FILE* f_maps = fopen("/proc/self/maps", "r");
    if (f_maps == NULL)
    {
        return -1;
    }

    char scn_buf[64];
    snprintf(scn_buf, sizeof(scn_buf), "%%" SCNxPTR "-%%" SCNxPTR " %%4s %%lx %%*x:%%*x %%*d %%%zus", size - 1);

    char line[1024];
    while (fgets(line, sizeof(line), f_maps))
    {
        if (sscanf(line, scn_buf, &base_addr, &end_addr, perm, &offset, buffer) != 5)
        {
            continue;
        }

        if (base_addr <= addr && addr <= end_addr)
        {
            ret = 0;
            goto fin;
        }
    }

fin:
    fclose(f_maps);
    return ret;
}

static size_t _elf_get_function_size_from_object(const char* path, void* symbol)
{
    size_t ret = (size_t)-1;
    elf_symbol_t* symbol_list = NULL;
    FILE* f_exe = fopen(path, "rb");

    uintptr_t relocation = (uintptr_t)elf_get_relocation_by_addr(symbol);
    if (relocation == 0)
    {
        LOG("get relocation for symbol(%p) failed", symbol);
        ret = (size_t)-1;
        goto fin;
    }

    uintptr_t target_addr = (uintptr_t)symbol - relocation;

    elf_info_t* info = NULL;
    if (elf_parser_file(&info, f_exe) != 0)
    {
        LOG("parser file(%s) failed", path);
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

int elf_inject_got_patch(void** token, void** fn_call, const char* name, void* detour)
{
    inject_got_ctx_t* helper = calloc(1, sizeof(inject_got_ctx_t));
    helper->name = name;
    helper->detour = detour;
    helper->inject_ret = UHOOK_UNKNOWN;
    helper->page_size = _get_page_size();

    dl_iterate_phdr(_unix_dl_iterate_phdr_got, helper);

    int ret = helper->inject_ret;
    if (helper->origin == NULL || ret != UHOOK_SUCCESS)
    {
        free(helper);
        return ret;
    }

    *token = helper;
    *fn_call = helper->origin;

    return UHOOK_SUCCESS;
}

void elf_inject_got_unpatch(void* token)
{
    inject_got_ctx_t* helper = token;

    if (helper->inject_info.addr_relplt != 0)
    {
        //LOG("restore .rel(a).plt region(%p) with function(%p)", (void*)helper->inject_info.addr_relplt, helper->origin);
        _elf_replace_function(helper, helper->inject_info.addr_relplt, helper->origin, NULL);
    }
    if (helper->inject_info.addr_reldyn != 0)
    {
        //LOG("restore .rel(a).dyn region(%p) with function(%p)", (void*)helper->inject_info.addr_reldyn, helper->origin);
        _elf_replace_function(helper, helper->inject_info.addr_reldyn, helper->origin, NULL);
    }

    free(helper);
}

void* elf_get_relocation_by_addr(void* symbol)
{
    relocation_helper_t helper;
    helper.ret = -1;
    helper.loc_addr = 0;
    helper.symbol_addr = symbol;

    dl_iterate_phdr(_elf_dl_iterate_phdr_callback, &helper);

    if (helper.ret < 0)
    {
        return NULL;
    }

    return (void*)helper.loc_addr;
}

/**
 * @return ((size_t)-1) is failure, otherwise success.
 */
size_t elf_get_function_size(void* symbol)
{
    char path_buffer[256];
    if (_elf_find_path((uintptr_t)symbol, path_buffer, sizeof(path_buffer)) < 0)
    {
        LOG("cannot find path for symbol(%p)", symbol);
        return (size_t)-1;
    }

    return _elf_get_function_size_from_object(path_buffer, symbol);
}

void uhook_dump_phdr(void)
{
    dl_iterate_phdr(_elf_dump_phdr_callback, NULL);
}
