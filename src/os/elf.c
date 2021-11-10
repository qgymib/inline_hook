#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include "uhook.h"
#include "os/elfparser.h"
#include "os/elf.h"

#define INLINE_HOOK_DEBUG
#include "log.h"

typedef struct inject_got_ctx
{
    const char*     name;
    void*           detour;
    void*           origin;
    size_t          symidx;

    struct
    {
        ElfW(Dyn)*  dyn_phdr;
        size_t      dyn_phdr_size;

        const char* strtab;         /**< .dynstr (string-table) */
        ElfW(Sym)*  symtab;         /**< .dynsym (symbol-index to string-table's offset) */
        int         is_rela;
        ElfW(Addr)  relplt;         /**< .rel.plt or .rela.plt */
        ElfW(Word)  relplt_sz;
        ElfW(Addr)  reldyn;         /**< .rel.dyn or .rela.dyn */
        ElfW(Word)  reldyn_sz;

        /* ELF Hash */
        uint32_t*   bucket;
        uint32_t    bucket_cnt;
        uint32_t*   chain;
        uint32_t    chain_cnt;      /**< invalid for GNU hash */

        /* GNU Hash */
        ElfW(Addr)* bloom;          /**< Check this value for GNU Hash usage */
        size_t      symoffset;
        size_t      bloom_sz;
        size_t      bloom_shift;
    } phdr_info;
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
    if (i < self->phdr_info.symoffset) return -1;

    //loop through the chain
    while (1)
    {
        const char* symname = self->phdr_info.strtab + self->phdr_info.symtab[i].st_name;
        const uint32_t  symhash = self->phdr_info.chain[i - self->phdr_info.symoffset];

        if ((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname))
        {
            *symidx = i;
            LOG("found %s at symidx: %zu (GNU_HASH DEF)", symbol, *symidx);
            return 0;
        }

        //chain ends with an element with the lowest bit set to 1
        if (symhash & (uint32_t)1) break;

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

static int _unix_dl_iterate_phdr_got(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;

    inject_got_ctx_t* helper = data;

    /* find PT_DYNAMIC phdr */
    helper->phdr_info.dyn_phdr = _unix_get_dyn_phdr(info, &helper->phdr_info.dyn_phdr_size);
    if (helper->phdr_info.dyn_phdr == NULL)
    {
        return 0;
    }
    LOG("phdr_dyn location: %p@%s", helper->phdr_info.dyn_phdr, info->dlpi_name);

    /* Parser PT_DYNAMIC program header */
    _unix_parser_dyn_phdr(helper, helper->phdr_info.dyn_phdr, helper->phdr_info.dyn_phdr_size);

    if (_unix_find_symidx_by_name(helper, helper->name, &helper->symidx) < 0)
    {/* Not found, find next shared phdr */
        return 0;
    }

    // TODO
    return 0;
}

static int _elf_dl_iterate_phdr_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;

    uintptr_t* p_ret = data;
    *p_ret = info->dlpi_addr;

    return 1;
}

int elf_inject_got_patch(void** token, void** fn_call, const char* name, void* detour)
{
    inject_got_ctx_t* helper = calloc(1, sizeof(inject_got_ctx_t));
    helper->name = name;
    helper->detour = detour;

    dl_iterate_phdr(_unix_dl_iterate_phdr_got, &helper);

    if (helper->origin == NULL)
    {
        free(helper);
        return UHOOK_GOTNOTFOUND;
    }

    *token = helper;
    *fn_call = helper->origin;

    return UHOOK_SUCCESS;
}

void elf_inject_got_unpatch(void* token)
{
    inject_got_ctx_t* helper = token;

    // TODO restore GOT

    free(helper);
}

void* elf_get_relocation(void)
{
    uintptr_t ret = 0;
    dl_iterate_phdr(_elf_dl_iterate_phdr_callback, &ret);
    return (void*)ret;
}

/**
 * @return ((size_t)-1) is failure, otherwise success.
 */
size_t elf_get_function_size(const void* addr)
{
    size_t ret = (size_t)-1;
    elf_symbol_t* symbol_list = NULL;
    FILE* f_exe = fopen("/proc/self/exe", "rb");
    uintptr_t relocation = (uintptr_t)elf_get_relocation();
    uintptr_t target_addr = (uintptr_t)addr - relocation;

    elf_info_t* info = NULL;
    if (elf_parser_file(&info, f_exe) != 0)
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
