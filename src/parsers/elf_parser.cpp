#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <algorithm>
#include "elf.hpp"

static inline bool inRange(size_t base, size_t need, size_t size) {
    return base <= size && need <= size && base <= need;
}

class ELFParser : public BaseParser {
public:
    std::string name() const override { return "ELF"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        return offset + 4 <= blob.size() &&
               blob[offset] == 0x7F &&
               blob[offset + 1] == 'E' &&
               blob[offset + 2] == 'L' &&
               blob[offset + 3] == 'F';
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult root;
        root.offset = offset;
        root.type = "ELF";
        root.info = "Executable and Linkable Format";
        root.isValid = false;
        root.length = 0;

        // Ensure we have at least EI_NIDENT bytes (16) to read class
        if (offset + EI_NIDENT > blob.size()) {
            root.info = "Truncated ELF ident";
            root.length = blob.size() - offset;
            return root;
        }

        const unsigned char ei_class = blob[offset + EI_CLASS];
        size_t maxEnd = 0;

        // Always include the ELF header itself as a candidate end
        if (ei_class == ELFCLASS32) {
            if (offset + sizeof(Elf32_Ehdr) > blob.size()) {
                root.info = "Truncated ELF32 header";
                root.length = blob.size() - offset;
                return root;
            }

            const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(&blob[offset]);

            // Candidate: end of header
            maxEnd = std::max(maxEnd, static_cast<size_t>(ehdr->e_ehsize));

            // Resolve program header count (extended PN_XNUM via sh_info of section 0)
            uint16_t phnum = ehdr->e_phnum;
            if (phnum == PN_XNUM && ehdr->e_shoff && ehdr->e_shentsize >= sizeof(Elf32_Shdr) && ehdr->e_shnum > 0) {
                if (offset + ehdr->e_shoff + ehdr->e_shentsize <= blob.size()) {
                    const Elf32_Shdr* sh0 = reinterpret_cast<const Elf32_Shdr*>(&blob[offset + ehdr->e_shoff]);
                    phnum = static_cast<uint16_t>(sh0->sh_info);
                }
            }

            // Candidate: end of program header table
            if (ehdr->e_phoff && phnum > 0) {
                size_t phTableEnd = ehdr->e_phoff + static_cast<size_t>(phnum) * ehdr->e_phentsize;
                maxEnd = std::max(maxEnd, phTableEnd);
            }

            // Program headers segments
            if (ehdr->e_phoff && phnum > 0) {
                for (uint32_t i = 0; i < phnum; i++) {
                    size_t entOff = ehdr->e_phoff + i * ehdr->e_phentsize;
                    if (offset + entOff + sizeof(Elf32_Phdr) > blob.size()) break;
                    const Elf32_Phdr* ph = reinterpret_cast<const Elf32_Phdr*>(&blob[offset + entOff]);
                    size_t end = static_cast<size_t>(ph->p_offset) + static_cast<size_t>(ph->p_filesz);
                    maxEnd = std::max(maxEnd, end);
                }
            }

            // Resolve section header count (extended via sh_size of section 0 when e_shnum == 0)
            uint16_t shnum = ehdr->e_shnum;
            if (shnum == 0 && ehdr->e_shoff && ehdr->e_shentsize >= sizeof(Elf32_Shdr)) {
                if (offset + ehdr->e_shoff + sizeof(Elf32_Shdr) <= blob.size()) {
                    const Elf32_Shdr* sh0 = reinterpret_cast<const Elf32_Shdr*>(&blob[offset + ehdr->e_shoff]);
                    shnum = static_cast<uint16_t>(sh0->sh_size);
                }
            }

            // Candidate: end of section header table
            if (ehdr->e_shoff && shnum > 0) {
                size_t shTableEnd = ehdr->e_shoff + static_cast<size_t>(shnum) * ehdr->e_shentsize;
                maxEnd = std::max(maxEnd, shTableEnd);
            }

            // Sections
            if (ehdr->e_shoff && shnum > 0) {
                for (uint32_t i = 0; i < shnum; i++) {
                    size_t entOff = ehdr->e_shoff + i * ehdr->e_shentsize;
                    if (offset + entOff + sizeof(Elf32_Shdr) > blob.size()) break;
                    const Elf32_Shdr* sh = reinterpret_cast<const Elf32_Shdr*>(&blob[offset + entOff]);
                    size_t end = static_cast<size_t>(sh->sh_offset) + static_cast<size_t>(sh->sh_size);
                    maxEnd = std::max(maxEnd, end);
                }
            }
        } else if (ei_class == ELFCLASS64) {
            if (offset + sizeof(Elf64_Ehdr) > blob.size()) {
                root.info = "Truncated ELF64 header";
                root.length = blob.size() - offset;
                return root;
            }

            const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(&blob[offset]);

            // Candidate: end of header
            maxEnd = std::max(maxEnd, static_cast<size_t>(ehdr->e_ehsize));

            // Resolve program header count (extended PN_XNUM)
            uint16_t phnum = ehdr->e_phnum;
            if (phnum == PN_XNUM && ehdr->e_shoff && ehdr->e_shentsize >= sizeof(Elf64_Shdr) && ehdr->e_shnum > 0) {
                if (offset + ehdr->e_shoff + sizeof(Elf64_Shdr) <= blob.size()) {
                    const Elf64_Shdr* sh0 = reinterpret_cast<const Elf64_Shdr*>(&blob[offset + ehdr->e_shoff]);
                    phnum = static_cast<uint16_t>(sh0->sh_info);
                }
            }

            // Candidate: end of program header table
            if (ehdr->e_phoff && phnum > 0) {
                size_t phTableEnd = static_cast<size_t>(ehdr->e_phoff) + static_cast<size_t>(phnum) * ehdr->e_phentsize;
                maxEnd = std::max(maxEnd, phTableEnd);
            }

            // Program headers segments
            if (ehdr->e_phoff && phnum > 0) {
                for (uint32_t i = 0; i < phnum; i++) {
                    size_t entOff = static_cast<size_t>(ehdr->e_phoff) + i * ehdr->e_phentsize;
                    if (offset + entOff + sizeof(Elf64_Phdr) > blob.size()) break;
                    const Elf64_Phdr* ph = reinterpret_cast<const Elf64_Phdr*>(&blob[offset + entOff]);
                    size_t end = static_cast<size_t>(ph->p_offset) + static_cast<size_t>(ph->p_filesz);
                    maxEnd = std::max(maxEnd, end);
                }
            }

            // Resolve section header count (extended when e_shnum == 0)
            uint16_t shnum = ehdr->e_shnum;
            if (shnum == 0 && ehdr->e_shoff && ehdr->e_shentsize >= sizeof(Elf64_Shdr)) {
                if (offset + ehdr->e_shoff + sizeof(Elf64_Shdr) <= blob.size()) {
                    const Elf64_Shdr* sh0 = reinterpret_cast<const Elf64_Shdr*>(&blob[offset + ehdr->e_shoff]);
                    shnum = static_cast<uint16_t>(sh0->sh_size);
                }
            }

            // Candidate: end of section header table
            if (ehdr->e_shoff && shnum > 0) {
                size_t shTableEnd = static_cast<size_t>(ehdr->e_shoff) + static_cast<size_t>(shnum) * ehdr->e_shentsize;
                maxEnd = std::max(maxEnd, shTableEnd);
            }

            // Sections
            if (ehdr->e_shoff && shnum > 0) {
                for (uint32_t i = 0; i < shnum; i++) {
                    size_t entOff = static_cast<size_t>(ehdr->e_shoff) + i * ehdr->e_shentsize;
                    if (offset + entOff + sizeof(Elf64_Shdr) > blob.size()) break;
                    const Elf64_Shdr* sh = reinterpret_cast<const Elf64_Shdr*>(&blob[offset + entOff]);
                    size_t end = static_cast<size_t>(sh->sh_offset) + static_cast<size_t>(sh->sh_size);
                    maxEnd = std::max(maxEnd, end);
                }
            }
        } else {
            root.info = "Unknown ELF class";
            root.length = blob.size() - offset;
            return root;
        }

        // If nothing was found, at least the header size applies
        if (maxEnd == 0) {
            maxEnd = 16; // minimal ident read; but prefer e_ehsize when available (handled above)
        }

        // Finalize: maxEnd is relative to the ELF file start.
        // Clamp to available blob region and mark valid.
        size_t available = blob.size() - offset;
        root.length = std::min(maxEnd, available);
        root.isValid = (root.length >= sizeof(Elf32_Ehdr)); // heuristic: at least header present

        // Optional: include class in info
        std::ostringstream oss;
        oss << "ELF" << ((ei_class == ELFCLASS64) ? "64" : "32");
        root.info = oss.str();

        return root;
    }
};

REGISTER_PARSER(ELFParser)
