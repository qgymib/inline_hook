#ifndef __INLINE_HOOK_ELFPARSER_H__
#define __INLINE_HOOK_ELFPARSER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdio.h>

/**
 * @brief 
 * @see https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
 */
typedef struct elf_file_header
{
    /**
     * 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
     */
    uint8_t f_EI_MAG[4];

    /**
     * This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
     */
    uint8_t f_EI_CLASS;

    /**
     * This byte is set to either 1 or 2 to signify little or big endianness, respectively.
     * This affects interpretation of multi-byte fields starting with offset 0x10.
     */
    uint8_t f_EI_DATA;

    /**
     * Set to 1 for the original and current version of ELF.
     */
    uint8_t f_EI_VERSION;

    /**
     * @brief Identifies the target operating system ABI.
     * 
     * | Value | ABI                           |
     * | ----- | ----------------------------- |
     * | 0x00  | System V                      |
     * | 0x01  | HP-UX                         |
     * | 0x02  | NetBSD                        |
     * | 0x03  | Linux                         |
     * | 0x04  | GNU Hurd                      |
     * | 0x06  | Solaris                       |
     * | 0x07  | AIX                           |
     * | 0x08  | IRIX                          |
     * | 0x09  | FreeBSD                       |
     * | 0x0A  | Tru64                         |
     * | 0x0B  | Novell Modesto                |
     * | 0x0C  | OpenBSD                       |
     * | 0x0D  | OpenVMS                       |
     * | 0x0E  | NonStop Kernel                |
     * | 0x0F  | AROS                          |
     * | 0x10  | Fenix OS                      |
     * | 0x11  | CloudABI                      |
     * | 0x12  | Stratus Technologies OpenVOS  |
     */
    uint8_t f_EI_OSABI;

    /**
     * @brief Further specifies the ABI version.
     *
     * Its interpretation depends on the target ABI. Linux kernel (after at least 2.6)
     * has no definition of it,[6] so it is ignored for statically-linked executables.
     * In that case, offset and size of EI_PAD are 8.
     * 
     * glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version
     * of the dynamic linker: it defines a list of dynamic linker's features, treats
     * e_ident[EI_ABIVERSION] as a feature level requested by the shared object
     * (executable or dynamic library) and refuses to load it if an unknown feature
     * is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.
     */
    uint8_t f_EI_ABIVERSION;

    /**
     * currently unused, should be filled with zeros.
     */
    uint8_t f_EI_PAD[7];

    /**
     * @brief Identifies object file type.
     * 
     * |Value  | Type      |
     * | ----- | --------- |
     * |0x00   | ET_NONE   |
     * |0x01   | ET_REL    |
     * |0x02   | ET_EXEC   |
     * |0x03   | ET_DYN    |
     * |0x04   | ET_CORE   |
     * |0xFE00 | ET_LOOS   |
     * |0xFEFF | ET_HIOS   |
     * |0xFF00 | ET_LOPROC |
     * |0xFFFF | ET_HIPROC |
     */
    uint16_t e_type;

    /**
     * @brief Specifies target instruction set architecture.
     * @see https://en.wikipedia.org/wiki/Instruction_set_architecture
     */
    uint16_t e_machine;

    /**
     * Set to 1 for the original version of ELF.
     */
    uint32_t e_version;

    /**
     * @brief This is the memory address of the entry point from where the process starts executing.
     * 
     * This field is either 32 or 64 bits long depending on the format defined earlier.
     */
    uint64_t e_entry;

    /**
     * @brief Points to the start of the program header table.
     * 
     * It usually follows the file header immediately, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
     */
    uint64_t e_phoff;

    /**
     * Points to the start of the section header table.
     */
    uint64_t e_shoff;

    /**
     * Interpretation of this field depends on the target architecture.
     */
    uint32_t e_flags;

    /**
     * Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
     */
    uint16_t e_ehsize;

    /**
     * Contains the size of a program header table entry.
     */
    uint16_t e_phentsize;

    /**
     * Contains the number of entries in the program header table.
     */
    uint16_t e_phnum;

    /**
     * Contains the size of a section header table entry.
     */
    uint16_t e_shentsize;

    /**
     * Contains the number of entries in the section header table.
     */
    uint16_t e_shnum;

    /**
     * Contains index of the section header table entry that contains the section names.
     */
    uint16_t e_shstrndx;
}elf_file_header_t;

typedef struct elf_program_header
{
    /**
     * Identifies the type of the segment.
     * | Value         | Name          | Meaning                                              |
     * | ------------- | ------------- | ---------------------------------------------------- |
     * | 0x00000000    | PT_NULL       | Program header table entry unused.                   |
     * | 0x00000001    | PT_LOAD       | Loadable segment.                                    |
     * | 0x00000002    | PT_DYNAMIC    | Dynamic linking information.                         |
     * | 0x00000003    | PT_INTERP     | Interpreter information.                             |
     * | 0x00000004    | PT_NOTE       | Auxiliary information.                               |
     * | 0x00000005    | PT_SHLIB      | Reserved.                                            |
     * | 0x00000006    | PT_PHDR       | Segment containing program header table itself.      |
     * | 0x00000007    | PT_TLS        | Thread-Local Storage template.                       |
     * | 0x60000000    | PT_LOOS       | Reserved inclusive range. Operating system specific. |
     * | 0x6FFFFFFF    | PT_HIOS       |                                                      |
     * | 0x70000000    | PT_LOPROC     | Reserved inclusive range. Processor specific.        |
     * | 0x7FFFFFFF    | PT_HIPROC     |                                                      |
     */
    uint32_t p_type;

    /**
     * Segment-dependent flags.
     */
    uint32_t p_flags;

    /**
     * Offset of the segment in the file image.
     */
    uint64_t p_offset;

    /**
     * Virtual address of the segment in memory.
     */
    uint64_t p_vaddr;

    /**
     * On systems where physical address is relevant, reserved for segment's
     * physical address.
     */
    uint64_t p_paddr;

    /**
     * Size in bytes of the segment in the file image. May be 0.
     */
    uint64_t p_filesz;

    /**
     * Size in bytes of the segment in memory. May be 0.
     */
    uint64_t p_memsz;

    /**
     * 0 and 1 specify no alignment. Otherwise should be a positive, integral
     * power of 2, with p_vaddr equating p_offset modulus p_align.
     */
    uint64_t p_align;
}elf_program_header_t;

typedef struct elf_section_header
{
    /**
     * An offset to a string in the `.shstrtab` section that represents the name of this section.
     */
    uint32_t sh_name;

    /**
     * @brief Identifies the type of this header.
     * |Value      | Name              | Meaning                           |
     * | --------- | ----------------- | --------------------------------- |
     * |0x0        | SHT_NULL          | Section header table entry unused |
     * |0x1        | SHT_PROGBITS      | Program data                      |
     * |0x2        | SHT_SYMTAB        | Symbol table                      |
     * |0x3        | SHT_STRTAB        | String table                      |
     * |0x4        | SHT_RELA          | Relocation entries with addends   |
     * |0x5        | SHT_HASH          | Symbol hash table                 |
     * |0x6        | SHT_DYNAMIC       | Dynamic linking information       |
     * |0x7        | SHT_NOTE          | Notes                             |
     * |0x8        | SHT_NOBITS        | Program space with no data (bss)  |
     * |0x9        | SHT_REL           | Relocation entries, no addends    |
     * |0x0A       | SHT_SHLIB         | Reserved                          |
     * |0x0B       | SHT_DYNSYM        | Dynamic linker symbol table       |
     * |0x0E       | SHT_INIT_ARRAY    | Array of constructors             |
     * |0x0F       | SHT_FINI_ARRAY    | Array of destructors              |
     * |0x10       | SHT_PREINIT_ARRAY | Array of pre-constructors         |
     * |0x11       | SHT_GROUP         | Section group                     |
     * |0x12       | SHT_SYMTAB_SHNDX  | Extended section indices          |
     * |0x13       | SHT_NUM           | Number of defined types.          |
     * |0x60000000 | SHT_LOOS          | Start OS-specific.                |
     * |...    ... | ...               | ...                               |
     */
    uint32_t sh_type;

    /**
     * @brief Identifies the attributes of the section.
     * | Value         | Name                  | Meaning                                                      |
     * | ------------- | --------------------- | ------------------------------------------------------------ |
     * | 0x1           | SHF_WRITE             | Writable                                                     |
     * | 0x2           | SHF_ALLOC             | Occupies memory during execution                             |
     * | 0x4           | SHF_EXECINSTR         | Executable                                                   |
     * | 0x10          | SHF_MERGE             | Might be merged                                              |
     * | 0x20          | SHF_STRINGS           | Contains null-terminated strings                             |
     * | 0x40          | SHF_INFO_LINK         | 'sh_info' contains SHT index                                 |
     * | 0x80          | SHF_LINK_ORDER        | Preserve order after combining                               |
     * | 0x100         | SHF_OS_NONCONFORMING  | Non-standard OS specific handling required                   |
     * | 0x200         | SHF_GROUP             | Section is member of a group                                 |
     * | 0x400         | SHF_TLS               | Section hold thread-local data                               |
     * | 0x0ff00000    | SHF_MASKOS            | OS-specific                                                  |
     * | 0xf0000000    | SHF_MASKPROC          | Processor-specific                                           |
     * | 0x4000000     | SHF_ORDERED           | Special ordering requirement (Solaris)                       |
     * | 0x8000000     | SHF_EXCLUDE           | Section is excluded unless referenced or allocated (Solaris) |
     */
    uint64_t sh_flags;

    /**
     * Virtual address of the section in memory, for sections that are loaded.
     */
    uint64_t sh_addr;

    /**
     * Offset of the section in the file image.
     */
    uint64_t sh_offset;

    /**
     * Size in bytes of the section in the file image. May be 0.
     */
    uint64_t sh_size;

    /**
     * @brief Contains the section index of an associated section.
     *
     * This field is used for several purposes, depending on the type of section.
     */
    uint32_t sh_link;

    /**
     * @brief Contains extra information about the section.
     *
     * This field is used for several purposes, depending on the type of section.
     */
    uint32_t sh_info;

    /**
     * @brief Contains the required alignment of the section.
     *
     * This field must be a power of two.
     */
    uint64_t sh_addralign;

    /**
     * @brief Contains the size, in bytes, of each entry, for sections that contain fixed-size entries.
     *
     * Otherwise, this field contains zero.
     */
    uint64_t sh_entsize;
}elf_section_header_t;

/**
 * @brief Parser ELF file header
 * @param[out] dst  File header information
 * @param[in] addr  Buffer to parser
 * @param[in] size  Length of buffer
 * @return          How many bytes read
 */
int elf_parser_file_header(elf_file_header_t* dst, const void* addr, size_t size);

/**
 * @brief Parser program header
 * @param[out] dst      Program header
 * @param[in] header    File header
 * @param[in] addr      The same value as #elf_parser_file_header()
 * @param[in] size      The same value as #elf_parser_file_header()
 * @param[in] idx       Which header you want to parser
 * @return              Result
 */
int elf_parser_program_header(elf_program_header_t* dst,
    const elf_file_header_t* header, const void* addr, size_t size, size_t idx);

/**
 * @brief Parser section header
 * @param[out] dst      Section header
 * @param[in] header    File header
 * @param[in] addr      The same value as #elf_parser_file_header()
 * @param[in] size      The same value as #elf_parser_file_header()
 * @param[in] idx       Which header you want to parser
 * @return              Result
 */
int elf_parser_section_header(elf_section_header_t* dst,
    const elf_file_header_t* header, const void* addr, size_t size, size_t idx);

/**
 * @brief Dump ELF information from buffer
 * @param[in] io        File to store information
 * @param[in] buffer    Buffer to parser
 * @param[in] size      Buffer size
 * @return              How many bytes written.
 */
int elf_dump_buffer(FILE* io, const void* buffer, size_t size);

/**
 * @brief Dump ELF information from file
 * @param[in] io        File to store information
 * @param[in] src       File to parser ELF information
 * @return              How many bytes written.
 */
int elf_dump_file(FILE* io, FILE* src);

#ifdef __cplusplus
}
#endif
#endif
