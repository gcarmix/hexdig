#include "base_parser.hpp"
#include "parser_registration.hpp"
#include "helpers.hpp"
#include <string>
#include <sstream>
#include <algorithm>
#include <cstdint>

// Thin Mach-O parser. Recognises the four byte patterns of a thin Mach-O
// header (32/64-bit, BE/LE), validates filetype and load-command counts,
// then walks LC_SEGMENT/LC_SEGMENT_64 to compute the on-disk footprint.
//
// Fat Mach-O (CAFEBABE / CAFEBABF) is intentionally not handled here: the
// magic collides with Java class files and disambiguating requires
// validating the architecture table, which we can add later if needed.

namespace {

// Load command codes (low 31 bits; the high bit is the LC_REQ_DYLD marker).
constexpr uint32_t LC_SEGMENT    = 0x01;
constexpr uint32_t LC_SEGMENT_64 = 0x19;

}  // namespace

class MachOParser : public BaseParser {
public:
    std::string name() const override { return "MachO"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 4 > blob.size()) return false;
        uint8_t b0 = blob[offset], b1 = blob[offset+1],
                b2 = blob[offset+2], b3 = blob[offset+3];
        // Thin Mach-O: 32/64-bit, BE/LE byte orderings.
        return (b0==0xFE && b1==0xED && b2==0xFA && (b3==0xCE || b3==0xCF)) ||
               (b0==0xCE && b1==0xFA && b2==0xED && b3==0xFE) ||
               (b0==0xCF && b1==0xFA && b2==0xED && b3==0xFE);
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "MachO";
        // No extractor — Mach-O acts as an identification "shield" to keep the
        // scanner from descending into a known executable region and matching
        // every parser's magic by chance.
        r.isValid = false;
        r.length = 0;

        if (offset + 4 > blob.size()) {
            r.info = "Truncated Mach-O magic";
            return r;
        }

        // Determine endianness and word size from the byte pattern of the magic.
        uint8_t b0 = blob[offset], b1 = blob[offset+1],
                b2 = blob[offset+2], b3 = blob[offset+3];
        bool isLE, is64;
        if      (b0==0xFE && b1==0xED && b2==0xFA && b3==0xCE) { isLE=false; is64=false; }
        else if (b0==0xCE && b1==0xFA && b2==0xED && b3==0xFE) { isLE=true;  is64=false; }
        else if (b0==0xFE && b1==0xED && b2==0xFA && b3==0xCF) { isLE=false; is64=true;  }
        else if (b0==0xCF && b1==0xFA && b2==0xED && b3==0xFE) { isLE=true;  is64=true;  }
        else { r.info = "Invalid Mach-O magic"; return r; }

        const size_t hdrSize = is64 ? 32u : 28u;
        if (offset + hdrSize > blob.size()) {
            r.info = "Truncated Mach-O header";
            return r;
        }

        auto rd32 = [&](size_t off) -> uint32_t {
            return isLE ? read_le32(blob, off) : read_be32(blob, off);
        };

        uint32_t cputype    = rd32(offset + 4);
        uint32_t filetype   = rd32(offset + 12);
        uint32_t ncmds      = rd32(offset + 16);
        uint32_t sizeofcmds = rd32(offset + 20);

        // Filetype must be one of the documented MH_* values (1..12).
        if (filetype == 0 || filetype > 12) {
            r.info = "Unknown Mach-O filetype (likely false positive)";
            return r;
        }

        // Plausibility for ncmds / sizeofcmds.
        size_t available = blob.size() - offset;
        if (ncmds == 0 || ncmds > 0x10000 ||
            sizeofcmds < 8 || sizeofcmds > available - hdrSize) {
            r.info = "Implausible Mach-O load-command counts";
            return r;
        }

        // Walk load commands and accumulate the maximum on-disk extent
        // contributed by LC_SEGMENT / LC_SEGMENT_64 entries.
        size_t maxEnd = hdrSize + sizeofcmds;
        size_t lcOff = offset + hdrSize;
        size_t lcEnd = std::min(lcOff + sizeofcmds, blob.size());

        for (uint32_t i = 0; i < ncmds; ++i) {
            if (lcOff + 8 > lcEnd) break;
            uint32_t cmd     = rd32(lcOff) & 0x7FFFFFFFu;  // strip LC_REQ_DYLD bit
            uint32_t cmdsize = rd32(lcOff + 4);
            if (cmdsize < 8 || cmdsize > lcEnd - lcOff) break;

            if (cmd == LC_SEGMENT && cmdsize >= 56) {
                // segment_command (32-bit): cmd, cmdsize, segname[16],
                //   vmaddr u32, vmsize u32, fileoff u32, filesize u32, ...
                uint64_t fileoff  = rd32(lcOff + 8 + 16 + 8);
                uint64_t filesize = rd32(lcOff + 8 + 16 + 12);
                size_t end = (size_t)(fileoff + filesize);
                if (end > maxEnd) maxEnd = end;
            } else if (cmd == LC_SEGMENT_64 && cmdsize >= 72) {
                // segment_command_64: cmd, cmdsize, segname[16],
                //   vmaddr u64, vmsize u64, fileoff u64, filesize u64, ...
                uint64_t fileoff =
                      (uint64_t)rd32(lcOff + 8 + 16 + 16)
                    | ((uint64_t)rd32(lcOff + 8 + 16 + 20) << 32);
                uint64_t filesize =
                      (uint64_t)rd32(lcOff + 8 + 16 + 24)
                    | ((uint64_t)rd32(lcOff + 8 + 16 + 28) << 32);
                size_t end = (size_t)(fileoff + filesize);
                if (end > maxEnd) maxEnd = end;
            }
            lcOff += cmdsize;
        }

        r.length = std::min(maxEnd, available);
        r.isValid = true;

        const char* arch = "unknown";
        switch (cputype) {
            case 0x00000007u: arch = "x86";        break;
            case 0x01000007u: arch = "x86_64";     break;
            case 0x0000000Cu: arch = "ARM";        break;
            case 0x0100000Cu: arch = "ARM64";      break;
            case 0x0200000Cu: arch = "ARM64_32";   break;
            case 0x00000012u: arch = "PowerPC";    break;
            case 0x01000012u: arch = "PowerPC64";  break;
        }
        const char* type = "unknown";
        switch (filetype) {
            case 1:  type = "object";      break;
            case 2:  type = "executable";  break;
            case 3:  type = "FVM lib";     break;
            case 4:  type = "core";        break;
            case 5:  type = "preload";     break;
            case 6:  type = "dylib";       break;
            case 7:  type = "dylinker";    break;
            case 8:  type = "bundle";      break;
            case 9:  type = "dylib stub";  break;
            case 10: type = "dSYM";        break;
            case 11: type = "kext bundle"; break;
            case 12: type = "fileset";     break;
        }
        std::ostringstream info;
        info << "Mach-O " << (is64 ? "64-bit" : "32-bit")
             << " " << (isLE ? "LE" : "BE")
             << " " << arch << " " << type
             << ", ncmds=" << ncmds;
        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(MachOParser)
