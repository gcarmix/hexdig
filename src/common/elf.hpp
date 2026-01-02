#include <cstdint>

// Indexes into e_ident[]
#define EI_MAG0     0 // 0x7F
#define EI_MAG1     1 // 'E'
#define EI_MAG2     2 // 'L'
#define EI_MAG3     3 // 'F'
#define EI_CLASS    4 // File class
#define EI_DATA     5 // Data encoding
#define EI_VERSION  6 // File version
#define EI_OSABI    7 // OS/ABI identification
#define EI_ABIVERSION 8 // ABI version
#define EI_PAD      9 // Start of padding bytes
#define EI_NIDENT   16
#define PN_XNUM     0xFFFF

// Values for e_ident[EI_CLASS]
#define ELFCLASSNONE 0 // Invalid class
#define ELFCLASS32   1 // 32-bit objects
#define ELFCLASS64   2 // 64-bit objects
// ELF32 file header
struct Elf32_Ehdr {
    unsigned char e_ident[16]; // Magic number and other info
    uint16_t e_type;           // Object file type
    uint16_t e_machine;        // Architecture
    uint32_t e_version;        // Object file version
    uint32_t e_entry;          // Entry point virtual address
    uint32_t e_phoff;          // Program header table file offset
    uint32_t e_shoff;          // Section header table file offset
    uint32_t e_flags;          // Processor-specific flags
    uint16_t e_ehsize;         // ELF header size
    uint16_t e_phentsize;      // Program header entry size
    uint16_t e_phnum;          // Program header entry count
    uint16_t e_shentsize;      // Section header entry size
    uint16_t e_shnum;          // Section header entry count
    uint16_t e_shstrndx;       // Section header string table index
};

// ELF32 program header
struct Elf32_Phdr {
    uint32_t p_type;   // Segment type
    uint32_t p_offset; // Segment file offset
    uint32_t p_vaddr;  // Segment virtual address
    uint32_t p_paddr;  // Segment physical address
    uint32_t p_filesz; // Segment size in file
    uint32_t p_memsz;  // Segment size in memory
    uint32_t p_flags;  // Segment flags
    uint32_t p_align;  // Segment alignment
};

// ELF32 section header
struct Elf32_Shdr {
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint32_t sh_flags;     // Section flags
    uint32_t sh_addr;      // Section virtual address
    uint32_t sh_offset;    // Section file offset
    uint32_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint32_t sh_addralign; // Section alignment
    uint32_t sh_entsize;   // Entry size if section holds table
};

// ELF64 file header
struct Elf64_Ehdr {
    unsigned char e_ident[16]; // Magic number and other info
    uint16_t e_type;           // Object file type
    uint16_t e_machine;        // Architecture
    uint32_t e_version;        // Object file version
    uint64_t e_entry;          // Entry point virtual address
    uint64_t e_phoff;          // Program header table file offset
    uint64_t e_shoff;          // Section header table file offset
    uint32_t e_flags;          // Processor-specific flags
    uint16_t e_ehsize;         // ELF header size
    uint16_t e_phentsize;      // Program header entry size
    uint16_t e_phnum;          // Program header entry count
    uint16_t e_shentsize;      // Section header entry size
    uint16_t e_shnum;          // Section header entry count
    uint16_t e_shstrndx;       // Section header string table index
};

// ELF64 program header
struct Elf64_Phdr {
    uint32_t p_type;   // Segment type
    uint32_t p_flags;  // Segment flags
    uint64_t p_offset; // Segment file offset
    uint64_t p_vaddr;  // Segment virtual address
    uint64_t p_paddr;  // Segment physical address
    uint64_t p_filesz; // Segment size in file
    uint64_t p_memsz;  // Segment size in memory
    uint64_t p_align;  // Segment alignment
};

// ELF64 section header
struct Elf64_Shdr {
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section flags
    uint64_t sh_addr;      // Section virtual address
    uint64_t sh_offset;    // Section file offset
    uint64_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
};
