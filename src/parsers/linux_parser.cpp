#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include "logger.hpp"

static bool matchLinuxBootImageMagic(const std::vector<uint8_t>& b, size_t off) {
    // b"\xb8\xc0\x07\x8e\xd8\xb8\x00\x90\x8e\xc0\xb9\x00\x01\x29\xf6\x29"
    static const uint8_t sig[] = {
        0xB8,0xC0,0x07,0x8E,0xD8,0xB8,0x00,0x90,0x8E,0xC0,0xB9,0x00,0x01,0x29,0xF6,0x29
    };
    return off + sizeof(sig) <= b.size() &&
           std::equal(sig, sig + sizeof(sig), &b[off]);
}

static bool hasHdrSAt(const std::vector<uint8_t>& b, size_t off) {
    // Expect "!HdrS" 514 bytes after magic
    const size_t hdrsOff = off + 514;
    if (hdrsOff + 5 > b.size()) return false;
    return b[hdrsOff] == '!' && b[hdrsOff+1] == 'H' && b[hdrsOff+2] == 'd' &&
           b[hdrsOff+3] == 'r' && b[hdrsOff+4] == 'S';
}

static bool matchArm64BootMagic(const std::vector<uint8_t>& b, size_t off) {
    // 56 bytes into the image: 8 zero bytes, then "ARMd"
    const size_t magicOffset = 0x30;
    if (off + magicOffset + 12 > b.size()) return false;
    for (int i = 0; i < 8; ++i) {
        if (b[off + magicOffset + i] != 0x00) return false;
    }
    return b[off + magicOffset + 8] == 'A' &&
           b[off + magicOffset + 9] == 'R' &&
           b[off + magicOffset + 10] == 'M' &&
           b[off + magicOffset + 11] == 'd';
}

static bool matchArmZImageMagic(const std::vector<uint8_t>& b, size_t off) {
    // Magic bytes: 0x18 0x28 0x6F 0x01 or 0x01 0x6F 0x28 0x18 (endianness variants)
    if (off + 4 > b.size()) return false;
    const uint8_t* p = &b[off];
    bool le = p[0] == 0x18 && p[1] == 0x28 && p[2] == 0x6F && p[3] == 0x01;
    bool be = p[0] == 0x01 && p[1] == 0x6F && p[2] == 0x28 && p[3] == 0x18;
    return le || be;
}

static std::string getCString(const uint8_t* data, size_t maxLen) {
    size_t len = 0;
    while (len < maxLen && data[len] != '\0') ++len;
    return std::string(reinterpret_cast<const char*>(data), len);
}

static std::string findKernelBanner(const std::vector<uint8_t>& b, size_t off = 0) {
    static const char needle[] = "Linux version ";
    auto it = std::search(b.begin() + off, b.end(), needle, needle + sizeof(needle) - 1);
    if (it == b.end()) return "";
    // read up to newline
    auto end = std::find(it, b.end(), '\n');
    return std::string(it, end+1);
}

static bool hasLinuxSymbolTable(const std::vector<uint8_t>& b) {
    // Same magic: "\x00""0""\x00""1""\x00""2"... up to "9"
    // Build the pattern once
    static std::vector<uint8_t> pat;
    if (pat.empty()) {
        for (char c = '0'; c <= '9'; ++c) {
            pat.push_back(0x00);
            pat.push_back(static_cast<uint8_t>(c));
        }
        pat.push_back(0x00);
    }
    size_t matches = 0;
    // Overlapping search
    for (size_t i = 0; i + pat.size() <= b.size(); ++i) {
        if (std::equal(pat.begin(), pat.end(), b.begin() + i)) {
            matches++;
        }
    }
    return matches == 1;
}

static bool bannerLooksValid(const std::string& s) {
    // Binwalk heuristics
    const size_t MIN_FILE_SIZE = 100 * 1024; // applied externally
    const size_t MIN_VERSION_STRING_LENGTH = 75;
    if (s.size() <= MIN_VERSION_STRING_LENGTH) return false;
    if (s.find("gcc ") == std::string::npos) return false;
    if (s.find('@') == std::string::npos) return false;
    if (s.back() != '\n') return false;
    // Period checks at expected positions relative to "Linux version "
    // "Linux version " is 15 chars; version like X.Y[.Z]
    const size_t base = 15;
    if (s.size() <= base + 18) return false;
    const auto& bytes = s;
    bool ok = (bytes[base] == '.') &&
              (bytes[base + 2] == '.' || bytes[base + 3] == '.');
    return ok;
}

class LinuxKernelParser : public BaseParser {
public:
    std::string name() const override { return "LinuxKernel"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        // Try boot image magic and validation
        if (matchLinuxBootImageMagic(blob, offset) && hasHdrSAt(blob, offset)) return true;
        if (matchArm64BootMagic(blob, offset)) return true;

        // ARM zImage: magic appears 36 bytes after real start, so allow backward correction
        const size_t MAGIC_OFFSET = 36;
        if (offset >= MAGIC_OFFSET && matchArmZImageMagic(blob, offset)) return true;

        // Kernel version banner anywhere (cheap pre-check at current offset)
        if (offset + 15 < blob.size()) {
            // exact match for the prefix bytes at current offset
            static const char prefix[] = "Linux version ";
            if (std::equal(prefix, prefix + sizeof(prefix) - 1, &blob[offset])) return true;
        }
        return false;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = name();
        r.isValid = true;

        // Linux boot image with !HdrS
        if (matchLinuxBootImageMagic(blob, offset) && hasHdrSAt(blob, offset)) {
            r.info = "Linux kernel boot image";
            r.length = blob.size() - offset;
            return r;
        }

        // ARM64 boot image
        if (matchArm64BootMagic(blob, offset)) {
            // True start is 0x30 bytes before this signature
            r.offset = offset - 0x30;
            // If you implement header parsing, set size/endian here
            r.info = "ARM64 boot image header detected";
            r.length = blob.size() - r.offset;
            return r;
        }

        // ARM zImage (adjust offset back by 36 bytes)
        const size_t MAGIC_OFFSET = 36;
        if (offset >= MAGIC_OFFSET && matchArmZImageMagic(blob, offset)) {
            r.extractorType = "XZ";
            r.offset = offset - MAGIC_OFFSET;
            r.info = "ARM zImage header detected";
            r.length = blob.size() - r.offset;
            return r;
        }

        // Kernel banner detection (vmlinux or decompressed kernel)
        std::string banner = findKernelBanner(blob, offset);
        if (!banner.empty()) {
            // Heuristics for confidence and symbol table
            bool valid = bannerLooksValid(banner);
            bool symtab = hasLinuxSymbolTable(blob);

            // If symbol table is present, assume raw vmlinux (full file)
            if (symtab) {
                r.offset = 0;
                r.length = blob.size();
                r.info = banner.substr(0, banner.size() - (banner.back() == '\n' ? 1 : 0)) +
                         ", has symbol table: true";
            } else {
                r.length = banner.size();
                r.info = banner.substr(0, banner.size() - (banner.back() == '\n' ? 1 : 0)) +
                         ", has symbol table: false";
            }
            r.confident = false;
            r.isValid = valid;
            return r;
        }

        // Fallback
        r.info = "No magic at start; consider scanning for ELF header or decompressing payload";
        r.length = blob.size() - offset;
        return r;
    }
};

//REGISTER_PARSER(LinuxKernelParser)