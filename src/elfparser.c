#include "elfparser.h"
#include <string.h>
#include <stdlib.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#   define HOST_EI_DATA 1
#elif __BYTE_ORDER == __BIG_ENDIAN
#   define HOST_EI_DATA 2
#else
#   error unknown endian
#endif

#define ELF_FILE_HEADER_32_SIZE 52
#define ELF_FILE_HEADER_64_SIZE 64

#define ELF_PROGRAM_HEADER_32_SIZE  32
#define ELF_PROGRAM_HEADER_64_SIZE  56

#define ELF_SECTION_HEADER_32_SIZE  40
#define ELF_SECTION_HEADER_64_SIZE  64

union ELF_U16
{
    uint16_t    val;
    uint8_t     u[2];
};

union ELF_U32
{
    uint32_t    val;
    uint8_t     u[4];
};

union ELF_U64
{
    uint64_t    val;
    uint8_t     u[8];
};

/**
 * @brief Parser 16bit data as uint16_t
 * @param[in] pdat      Buffer
 * @param[in] EI_DATA   Endian
 * @return              Result
 */
static uint16_t _elf_parser_16bit(const uint8_t* pdat, int f_EI_DATA)
{
    union ELF_U16 elf_u16;

    if (HOST_EI_DATA == f_EI_DATA)
    {
        elf_u16.u[0] = pdat[0];
        elf_u16.u[1] = pdat[1];
    }
    else
    {
        elf_u16.u[0] = pdat[1];
        elf_u16.u[1] = pdat[0];
    }
    return elf_u16.val;
}

/**
 * @brief Parser 32bit data as uint32_t
 * @param[in] pdat      Buffer
 * @param[in] EI_DATA   Endian
 * @return              Result
 */
static uint32_t _elf_parser_32bit(const uint8_t* pdat, int f_EI_DATA)
{
    union ELF_U32 elf_u32;

    if (HOST_EI_DATA == f_EI_DATA)
    {
        elf_u32.u[0] = pdat[0];
        elf_u32.u[1] = pdat[1];
        elf_u32.u[2] = pdat[2];
        elf_u32.u[3] = pdat[3];
    }
    else
    {
        elf_u32.u[0] = pdat[3];
        elf_u32.u[1] = pdat[2];
        elf_u32.u[2] = pdat[1];
        elf_u32.u[3] = pdat[0];
    }

    return elf_u32.val;
}

/**
 * @brief Parser 64bit data as uint64_t
 * @param[in] pdat      Buffer
 * @param[in] EI_DATA   Endian
 * @return              Result
 */
static uint64_t _elf_parser_64bit(const uint8_t* pdat, int f_EI_DATA)
{
    union ELF_U64 elf_u64;

    if (HOST_EI_DATA == f_EI_DATA)
    {
        elf_u64.u[0] = pdat[0];
        elf_u64.u[1] = pdat[1];
        elf_u64.u[2] = pdat[2];
        elf_u64.u[3] = pdat[3];
        elf_u64.u[4] = pdat[4];
        elf_u64.u[5] = pdat[5];
        elf_u64.u[6] = pdat[6];
        elf_u64.u[7] = pdat[7];
    }
    else
    {
        elf_u64.u[0] = pdat[7];
        elf_u64.u[1] = pdat[6];
        elf_u64.u[2] = pdat[5];
        elf_u64.u[3] = pdat[4];
        elf_u64.u[4] = pdat[3];
        elf_u64.u[5] = pdat[2];
        elf_u64.u[6] = pdat[1];
        elf_u64.u[7] = pdat[0];
    }
    return elf_u64.val;
}

static int _elf_parser_program32_header(elf_program_header_t* dst,
    const elf_file_header_t* header, const uint8_t* pdat, size_t size)
{
    size_t pos = 0;
    if (size < ELF_PROGRAM_HEADER_32_SIZE)
    {
        return -1;
    }

    dst->p_type = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_offset = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_vaddr = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_paddr = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_filesz = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_memsz = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_flags = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_align = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    return 0;
}

static int _elf_parser_program64_header(elf_program_header_t* dst,
    const elf_file_header_t* header, const uint8_t* pdat, size_t size)
{
    size_t pos = 0;
    if (size < ELF_PROGRAM_HEADER_64_SIZE)
    {
        return -1;
    }

    dst->p_type = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_flags = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->p_offset = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->p_vaddr = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->p_paddr = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->p_filesz = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->p_memsz = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->p_align = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    return 0;
}

static const char* _elf_dump_header_get_type(uint16_t type)
{
    switch (type)
    {
    case 0x00:      return "NONE";
    case 0x01:      return "REL";
    case 0x02:      return "EXEC";
    case 0x03:      return "DYN (Position-Independent Executable file)";
    case 0x04:      return "CORE";
    case 0xFE00:    return "LOOS";
    case 0xFEFF:    return "HIOS";
    case 0xFF00:    return "LOPROC";
    case 0xFFFF:    return "HIPROC";
    default:
        break;
    }
    return "[Unknown]";
}

static const char* _elf_dump_header_get_osabi(uint8_t osabi)
{
    switch (osabi)
    {
    case 0x00:  return "System V";
    case 0x01:  return "HP-UX";
    case 0x02:  return "NetBSD";
    case 0x03:  return "Linux";
    case 0x04:  return "GNU Hurd";
    case 0x06:  return "Solaris";
    case 0x07:  return "AIX";
    case 0x08:  return "IRIX";
    case 0x09:  return "FreeBSD";
    case 0x0A:  return "Tru64";
    case 0x0B:  return "Novell Modesto";
    case 0x0C:  return "OpenBSD";
    case 0x0D:  return "OpenVMS";
    case 0x0E:  return "NonStop Kernel";
    case 0x0F:  return "AROS";
    case 0x10:  return "Fenix OS";
    case 0x11:  return "CloudABI";
    case 0x12:  return "Stratus Technologies OpenVOS";
    default:    return "[Unknown]";
    }
}

static const char* _elf_dump_header_get_class(uint8_t ei_class)
{
    switch (ei_class)
    {
    case 1:     return "ELF32";
    case 2:     return "ELF64";
    default:    return "[Unknown]";
    }
}

static const char* _elf_dump_header_get_data(uint8_t ei_data)
{
    switch (ei_data)
    {
    case 1:     return "2's complement, little endian";
    case 2:     return "2's complement, big endian";
    default:    return "Unknown data format";
    }
}

static const char* _elf_dump_header_get_machine(uint16_t e_machine)
{
    switch (e_machine)
    {
    case 0x00:  return "No specific instruction set";
    case 0x01:  return "AT&T WE 32100";
    case 0x02:  return "SPARC";
    case 0x03:  return "x86";
    case 0x04:  return "Motorola 68000 (M68k)";
    case 0x05:  return "Motorola 88000 (M88k)";
    case 0x06:  return "Intel MCU";
    case 0x07:  return "Intel 80860";
    case 0x08:  return "MIPS";
    case 0x09:  return "IBM System/370";
    case 0x0A:  return "MIPS RS3000 Little-endian";
    case 0x0E:  return "Hewlett-Packard PA-RISC";
    case 0x0F:  return "Reserved for future use";
    case 0x13:  return "Intel 80960";
    case 0x14:  return "PowerPC";
    case 0x15:  return "PowerPC (64-bit)";
    case 0x16:  return "S390, including S390x";
    case 0x17:  return "IBM SPU/SPC";
    case 0x24:  return "NEC V800";
    case 0x25:  return "Fujitsu FR20";
    case 0x26:  return "TRW RH-32";
    case 0x27:  return "Motorola RCE";
    case 0x28:  return "ARM (up to ARMv7/Aarch32)";
    case 0x29:  return "Digital Alpha";
    case 0x2A:  return "SuperH";
    case 0x2B:  return "SPARC Version 9";
    case 0x2C:  return "Siemens TriCore embedded processor";
    case 0x2D:  return "Argonaut RISC Core";
    case 0x2E:  return "Hitachi H8/300";
    case 0x2F:  return "Hitachi H8/300H";
    case 0x30:  return "Hitachi H8S";
    case 0x31:  return "Hitachi H8/500";
    case 0x32:  return "IA-64";
    case 0x33:  return "Stanford MIPS-X";
    case 0x34:  return "Motorola ColdFire";
    case 0x35:  return "Motorola M68HC12";
    case 0x36:  return "Fujitsu MMA Multimedia Accelerator";
    case 0x37:  return "Siemens PCP";
    case 0x38:  return "Sony nCPU embedded RISC processor";
    case 0x39:  return "Denso NDR1 microprocessor";
    case 0x3A:  return "Motorola Star*Core processor";
    case 0x3B:  return "Toyota ME16 processor";
    case 0x3C:  return "STMicroelectronics ST100 processor";
    case 0x3D:  return "Advanced Logic Corp. TinyJ embedded processor family";
    case 0x3E:  return "Advanced Micro Devices X86-64";
    case 0x8C:  return "TMS320C6000 Family";
    case 0xAF:  return "MCST Elbrus e2k";
    case 0xB7:  return "ARM 64-bits (ARMv8/Aarch64)";
    case 0xF3:  return "RISC-V";
    case 0xF7:  return "Berkeley Packet Filter";
    case 0x101: return "WDC 65C816";
    default:    return "[Unknown]";
    }
}

static int _elf_dump_header(FILE* io, const elf_file_header_t* header)
{
    return fprintf(io,
        "Class:                             %s\n"
        "Data:                              %s\n"
        "Version:                           %d\n"
        "OS/ABI:                            %s\n"
        "ABI Version:                       %d\n"
        "Type:                              %s\n"
        "Machine:                           %s\n"
        "Version:                           0x%" PRIx32 "\n"
        "Entry point address:               0x%" PRIx64 "\n"
        "Start of program headers:          %" PRIu64 "\n"
        "Start of section headers:          %" PRIu64 "\n"
        "Flags:                             0x%" PRIx32 "\n"
        "Size of this header:               %u (bytes)\n"
        "Size of program headers:           %u (bytes)\n"
        "Number of program headers:         %u\n"
        "Size of section headers:           %u (bytes)\n"
        "Number of section headers:         %u\n"
        "Section header string table index: %u\n",
        _elf_dump_header_get_class(header->f_EI_CLASS),
        _elf_dump_header_get_data(header->f_EI_DATA),
        (int)header->f_EI_VERSION,
        _elf_dump_header_get_osabi(header->f_EI_OSABI),
        header->f_EI_ABIVERSION,
        _elf_dump_header_get_type(header->e_type),
        _elf_dump_header_get_machine(header->e_machine),
        header->e_version,
        header->e_entry,
        header->e_phoff,
        header->e_shoff,
        header->e_flags,
        (unsigned)header->e_ehsize,
        (unsigned)header->e_phentsize,
        (unsigned)header->e_phnum,
        (unsigned)header->e_shentsize,
        (unsigned)header->e_shnum,
        (unsigned)header->e_shstrndx);
}

static const char* _elf_dump_program_header_get_type(uint32_t p_type)
{
    switch (p_type)
    {
    case 0x00000000:    return "NULL";
    case 0x00000001:    return "LOAD";
    case 0x00000002:    return "DYNAMIC";
    case 0x00000003:    return "INTERP";
    case 0x00000004:    return "NOTE";
    case 0x00000005:    return "SHLIB";
    case 0x00000006:    return "PHDR";
    case 0x00000007:    return "TLS";
    case 0x60000000:    return "LOOS";
    case 0x6474e550:    return "GNU_EH_FRAME";
    case 0x6474e551:    return "GNU_STACK";
    case 0x6474e552:    return "GNU_RELRO";
    case 0x6FFFFFFF:    return "HIOS";
    case 0x70000000:    return "LOPROC";
    case 0x7FFFFFFF:    return "HIPROC";
    default:            return "[Unknown]";
    }
}

static int _elf_dump_program_header(FILE* io, const elf_program_header_t* program_hdr, int is_64bit)
{
    const int ptr_width = is_64bit ? 16 : 8;

    return fprintf(io,
        "%-*s 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx32 " %" PRIu64 "\n",
        12, _elf_dump_program_header_get_type(program_hdr->p_type),
        ptr_width, program_hdr->p_offset,
        ptr_width, program_hdr->p_vaddr,
        ptr_width, program_hdr->p_paddr,
        ptr_width, program_hdr->p_filesz,
        ptr_width, program_hdr->p_memsz,
        8, program_hdr->p_flags,
        program_hdr->p_align);
}

static int _elf_parser_section32_header(elf_section_header_t* dst,
    const elf_file_header_t* header, const uint8_t* pdat, size_t size)
{
    size_t pos = 0;
    if (size < ELF_SECTION_HEADER_32_SIZE)
    {
        return -1;
    }

    dst->sh_name = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_type = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_flags = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_addr = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_offset = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_size = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_link = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_info = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_addralign = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_entsize = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    return 0;
}

static int _elf_parser_section64_header(elf_section_header_t* dst,
    const elf_file_header_t* header, const uint8_t* pdat, size_t size)
{
    size_t pos = 0;
    if (size < ELF_SECTION_HEADER_64_SIZE)
    {
        return -1;
    }

    dst->sh_name = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_type = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_flags = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->sh_addr = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->sh_offset = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->sh_size = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->sh_link = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_info = _elf_parser_32bit(&pdat[pos], header->f_EI_DATA);
    pos += 4;

    dst->sh_addralign = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    dst->sh_entsize = _elf_parser_64bit(&pdat[pos], header->f_EI_DATA);
    pos += 8;

    return 0;
}

static int _elf_parser_program_header_ext(elf_program_header_t* dst,
    const elf_file_header_t* header, const void* addr, size_t size)
{
    if (header->f_EI_CLASS == 1)
    {
        return _elf_parser_program32_header(dst, header, addr, size);
    }
    else if (header->f_EI_CLASS == 2)
    {
        return _elf_parser_program64_header(dst, header, addr, size);
    }
    return -1;
}

static int _elf_parser_section_header_ext(elf_section_header_t* dst,
    const elf_file_header_t* header, const uint8_t* pdat, size_t size)
{
    if (header->f_EI_CLASS == 1)
    {
        return _elf_parser_section32_header(dst, header, pdat, size);
    }
    else if (header->f_EI_CLASS == 2)
    {
        return _elf_parser_section64_header(dst, header, pdat, size);
    }
    return -1;
}

static const char* _elf_dump_secion_header_get_type(uint32_t sh_type)
{
    switch (sh_type)
    {
    case 0x0:           return "NULL";
    case 0x1:           return "PROGBITS";
    case 0x2:           return "SYMTAB";
    case 0x3:           return "STRTAB";
    case 0x4:           return "RELA";
    case 0x5:           return "HASH";
    case 0x6:           return "DYNAMIC";
    case 0x7:           return "NOTE";
    case 0x8:           return "NOBITS";
    case 0x9:           return "REL";
    case 0x0A:          return "SHLIB";
    case 0x0B:          return "DYNSYM";
    case 0x0E:          return "INIT_ARRAY";
    case 0x0F:          return "FINI_ARRAY";
    case 0x10:          return "PREINIT_ARRAY";
    case 0x11:          return "GROUP";
    case 0x12:          return "SYMTAB_SHNDX";
    case 0x13:          return "NUM";
    case 0x60000000:    return "LOOS";
    default:            return "[Unknown]";
    }
}

static int _elf_dump_section_header(FILE* io, const elf_section_header_t* section_hdr, int is_64bit)
{
    const int ptr_width = is_64bit ? 16 : 8;

    return fprintf(io,
        "0x%08" PRIx32 " %-*s 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%0*" PRIx64 " 0x%08" PRIx32 " 0x%08" PRIx32 " 0x%0*" PRIx64 " 0x%0*" PRIx64 "\n",
        section_hdr->sh_name,
        13, _elf_dump_secion_header_get_type(section_hdr->sh_type),
        ptr_width, section_hdr->sh_flags,
        ptr_width, section_hdr->sh_addr,
        ptr_width, section_hdr->sh_offset,
        ptr_width, section_hdr->sh_size,
        section_hdr->sh_link,
        section_hdr->sh_info,
        ptr_width, section_hdr->sh_addralign,
        ptr_width, section_hdr->sh_entsize);
}

static int _elf_dump_print_program_title(FILE* io, uint8_t f_EI_CLASS)
{
    const int str_width = f_EI_CLASS == 2 ? 18 : 10;
    return fprintf(io, "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %s\n",
        12, "[Type]",
        str_width, "[Offset]",
        str_width, "[VirtAddr]",
        str_width, "[PhysAddr]",
        str_width, "[FileSiz]",
        str_width, "[MemSiz]",
        10, "[Flags]",
        "[Align]");
}

static int _elf_parser_file_header_from_file(elf_file_header_t* dst, FILE* src)
{
    uint8_t cache[ELF_FILE_HEADER_64_SIZE];
    
    if (fseek(src, 0, SEEK_SET) != 0)
    {
        return -1;
    }

    size_t read_size = fread(cache, 1, ELF_FILE_HEADER_64_SIZE, src);
    return elf_parser_file_header(dst, cache, read_size);
}

static int _elf_parser_program_header_from_file(elf_program_header_t* dst,
    FILE* file, const elf_file_header_t* file_hdr, size_t idx)
{
    uint8_t cache[ELF_PROGRAM_HEADER_64_SIZE];
    size_t target_pos = file_hdr->e_phoff + idx * file_hdr->e_phentsize;

    if (fseek(file, target_pos, SEEK_SET) != 0)
    {
        return -1;
    }

    size_t read_size = fread(cache, 1, file_hdr->e_phentsize, file);
    return _elf_parser_program_header_ext(dst, file_hdr, cache, read_size);
}

static int _elf_dump_print_section_title(FILE* io, uint8_t f_EI_CLASS)
{
    const int str_width = f_EI_CLASS == 2 ? 18 : 10;

    return fprintf(io,
        "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
        10, "[sh_name]",
        13, "[sh_type]",
        str_width, "[sh_flags]",
        str_width, "[sh_addr]",
        str_width, "[sh_offset]",
        str_width, "[sh_size]",
        10, "[sh_link]",
        10, "[sh_info]",
        str_width, "[sh_addralign]",
        str_width, "[sh_entsize]");
}

static int _elf_parser_section_header_from_file(elf_section_header_t* dst, FILE* file,
    const elf_file_header_t* file_hdr, size_t idx)
{
    uint8_t cache[ELF_SECTION_HEADER_64_SIZE];
    size_t target_pos = file_hdr->e_shoff + idx * file_hdr->e_shentsize;
    if (fseek(file, target_pos, SEEK_SET) != 0)
    {
        return -1;
    }

    size_t read_size = fread(cache, 1, file_hdr->e_shentsize, file);
    return _elf_parser_section_header_ext(dst, file_hdr, cache, read_size);
}

int elf_parser_file_header(elf_file_header_t* dst, const void* addr, size_t size)
{
    const uint8_t* pdat = addr;
    int pos = 0;

    /* 32bit ELF file header size */
    if (size < ELF_FILE_HEADER_32_SIZE)
    {
        return -1;
    }

    const uint8_t magic_header[4] = { 0x7f, 0x45, 0x4c, 0x46 };
    if (memcmp(addr, magic_header, sizeof(magic_header)) != 0)
    {
        return -1;
    }

    /* EI_MAG */
    memcpy(dst->f_EI_MAG, magic_header, sizeof(magic_header));
    pos += 4;

    dst->f_EI_CLASS = pdat[pos++];
    if (dst->f_EI_CLASS != 1 && dst->f_EI_CLASS != 2)
    {
        return -1;
    }

    /* 64bit ELF file header size */
    if (dst->f_EI_CLASS == 2 && size < ELF_FILE_HEADER_64_SIZE)
    {
        return -1;
    }

    dst->f_EI_DATA = pdat[pos++];
    if (dst->f_EI_DATA != 1 && dst->f_EI_DATA != 2)
    {
        return -1;
    }

    dst->f_EI_VERSION = pdat[pos++];
    dst->f_EI_OSABI = pdat[pos++];
    dst->f_EI_ABIVERSION = pdat[pos++];
    memcpy(dst->f_EI_PAD, &pdat[pos], sizeof(dst->f_EI_PAD));
    pos += 7;

    dst->e_type = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_machine = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_version = _elf_parser_32bit(&pdat[pos], dst->f_EI_DATA);
    pos += 4;

    if (dst->f_EI_CLASS == 1)
    {
        dst->e_entry = _elf_parser_32bit(&pdat[pos], dst->f_EI_DATA);
        pos += 4;
        dst->e_phoff = _elf_parser_32bit(&pdat[pos], dst->f_EI_DATA);
        pos += 4;
        dst->e_shoff = _elf_parser_32bit(&pdat[pos], dst->f_EI_DATA);
        pos += 4;
    }
    else
    {
        dst->e_entry = _elf_parser_64bit(&pdat[pos], dst->f_EI_DATA);
        pos += 8;
        dst->e_phoff = _elf_parser_64bit(&pdat[pos], dst->f_EI_DATA);
        pos += 8;
        dst->e_shoff = _elf_parser_64bit(&pdat[pos], dst->f_EI_DATA);
        pos += 8;
    }

    dst->e_flags = _elf_parser_32bit(&pdat[pos], dst->f_EI_DATA);
    pos += 4;

    dst->e_ehsize = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_phentsize = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_phnum = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_shentsize = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_shnum = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    dst->e_shstrndx = _elf_parser_16bit(&pdat[pos], dst->f_EI_DATA);
    pos += 2;

    return pos;
}

int elf_parser_program_header(elf_program_header_t* dst,
    const elf_file_header_t* header, const void* addr, size_t size, size_t idx)
{
    const uint8_t* max_pdat_pos = (uint8_t*)addr + size;
    const uint8_t* pdat = (uint8_t*)addr + header->e_phoff + idx * header->e_phentsize;
    if (idx >= header->e_phnum || pdat >= max_pdat_pos)
    {
        return -1;
    }

    size_t left_size = max_pdat_pos - pdat;
    return _elf_parser_program_header_ext(dst, header, pdat, left_size);
}

int elf_parser_section_header(elf_section_header_t* dst,
    const elf_file_header_t* header, const void* addr, size_t size, size_t idx)
{
    const uint8_t* max_pdat_pos = (uint8_t*)addr + size;
    const uint8_t* pdat = (uint8_t*)addr + header->e_shoff + idx * header->e_shentsize;
    if (idx >= header->e_shnum || pdat >= max_pdat_pos)
    {
        return -1;
    }

    size_t left_size = max_pdat_pos - pdat;
    return _elf_parser_section_header_ext(dst, header, pdat, left_size);
}

int elf_dump_buffer(FILE* io, const void* buffer, size_t size)
{
    int ret;
    size_t idx;
    int size_written = 0;

    elf_file_header_t file_hdr;
    if ((ret = elf_parser_file_header(&file_hdr, buffer, size)) < 0)
    {
        return ret;
    }
    if ((ret = _elf_dump_header(io, &file_hdr)) < 0)
    {
        return ret;
    }
    size_written += ret;

    elf_program_header_t program_hdr;
    if ((ret = _elf_dump_print_program_title(io, file_hdr.f_EI_CLASS)) < 0)
    {
        return ret;
    }
    size_written += ret;

    for (idx = 0; idx < file_hdr.e_phnum; idx++)
    {
        if ((ret = elf_parser_program_header(&program_hdr, &file_hdr, buffer, size, idx)) < 0)
        {
            return ret;
        }

        if ((ret = _elf_dump_program_header(io, &program_hdr, file_hdr.f_EI_CLASS == 2)) < 0)
        {
            return ret;
        }
        size_written += ret;
    }

    elf_section_header_t shstrtab_hdr;
    if ((ret = elf_parser_section_header(&shstrtab_hdr, &file_hdr, buffer, size, file_hdr.e_shstrndx)) < 0)
    {
        return ret;
    }

    elf_section_header_t section_hdr;
    for (idx = 0; idx < file_hdr.e_shnum; idx++)
    {
        if ((ret = elf_parser_section_header(&section_hdr, &file_hdr, buffer, size, idx)) < 0)
        {
            return ret;
        }

        if ((ret = _elf_dump_section_header(io, &section_hdr, file_hdr.f_EI_CLASS == 2)) < 0)
        {
            return ret;
        }
        size_written += ret;
    }

    return size_written;
}

int elf_parser_file(elf_info_t** dst, FILE* file)
{
    int ret;
    size_t idx;

    elf_file_header_t file_hdr;
    if ((ret = _elf_parser_file_header_from_file(&file_hdr, file)) < 0)
    {
        return ret;
    }

    elf_info_t* info = malloc(sizeof(elf_info_t) + sizeof(elf_program_header_t) * file_hdr.e_phnum
        + sizeof(elf_section_header_t) * file_hdr.e_shnum);
    if (info == NULL)
    {
        return -1;
    }
    memcpy(&info->file_hdr, &file_hdr, sizeof(file_hdr));
    info->data.source_type = ELF_SOURCE_POSIX_FILE;
    info->data.source.as_file = file;

    info->program_hdr = (elf_program_header_t*)((uint8_t*)info + sizeof(elf_info_t));
    for (idx = 0; idx < file_hdr.e_phnum; idx++)
    {
        if ((ret = _elf_parser_program_header_from_file(&info->program_hdr[idx], file, &file_hdr, idx)) < 0)
        {
            free(info);
            return ret;
        }
    }

    info->section_hdr = (elf_section_header_t*)((uint8_t*)info + sizeof(elf_info_t) +
        sizeof(elf_program_header_t) * file_hdr.e_phnum);
    for (idx = 0; idx < file_hdr.e_shnum; idx++)
    {
        if ((ret = _elf_parser_section_header_from_file(&info->section_hdr[idx], file, &file_hdr, idx)) < 0)
        {
            free(info);
            return ret;
        }
    }

    *dst = info;
    return ret;
}

int elf_dump_info(FILE* io, const elf_info_t* info)
{
    int ret;
    size_t idx;
    int written_size = 0;

    if ((ret = _elf_dump_header(io, &info->file_hdr)) < 0)
    {
        return ret;
    }
    written_size += ret;

    if ((ret = _elf_dump_print_program_title(io, info->file_hdr.f_EI_CLASS)) < 0)
    {
        return ret;
    }
    written_size += ret;

    for (idx = 0; idx < info->file_hdr.e_phnum; idx++)
    {
        if ((ret = _elf_dump_program_header(io, &info->program_hdr[idx], info->file_hdr.f_EI_CLASS == 2)) < 0)
        {
            return ret;
        }
        written_size += ret;
    }

    if ((ret = _elf_dump_print_section_title(io, info->file_hdr.f_EI_CLASS)) < 0)
    {
        return ret;
    }
    written_size += ret;

    for (idx = 0; idx < info->file_hdr.e_shnum; idx++)
    {
        if ((ret = _elf_dump_section_header(io, &info->section_hdr[idx], info->file_hdr.f_EI_CLASS == 2)) < 0)
        {
            return ret;
        }
        written_size += ret;
    }

    return written_size;
}

void elf_info_destroy(elf_info_t* info)
{
    free(info);
}
