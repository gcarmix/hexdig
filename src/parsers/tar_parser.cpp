#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <iostream>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

class TARParser : public BaseParser {
public:
    std::string name() const override { return "TAR"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override;
};

static std::string read_string(const uint8_t* buf, size_t len) {
    size_t n = 0;
    while (n < len && buf[n] != 0) n++;
    return std::string(reinterpret_cast<const char*>(buf), n);
}

static size_t read_octal(const uint8_t* buf, size_t len) {
    std::string s(reinterpret_cast<const char*>(buf), len);
    // Trim spaces and NULs
    size_t end = s.find_last_not_of(" \0", std::string::npos);
    if (end != std::string::npos) s = s.substr(0, end + 1);
    size_t val = 0;
    std::stringstream ss;
    ss << std::oct << s;
    ss >> val;
    return val;
}

// Known tar typeflags (POSIX + GNU + pax extensions).
static bool isKnownTarTypeflag(uint8_t t) {
    switch (t) {
        case '\0': case '0': case '1': case '2': case '3':
        case '4':  case '5': case '6': case '7':
        case 'g':  case 'x': case 'L': case 'K':
        case 'A':  case 'D': case 'M': case 'N':
        case 'S':  case 'V':
            return true;
    }
    return false;
}

// Classic tar header checksum: sum of all 512 bytes with the 8-byte chksum
// field (offset 148..155) replaced by ASCII spaces. Old writers treated
// bytes as signed — accept either interpretation.
static bool tarChecksumMatches(const uint8_t* hdr) {
    constexpr size_t CHK_OFF = 148;
    constexpr size_t CHK_LEN = 8;

    uint32_t unsigned_sum = 0;
    int32_t  signed_sum   = 0;
    for (size_t i = 0; i < 512; i++) {
        uint8_t b = (i >= CHK_OFF && i < CHK_OFF + CHK_LEN) ? uint8_t(' ') : hdr[i];
        unsigned_sum += b;
        signed_sum   += static_cast<int8_t>(b);
    }
    size_t stored = read_octal(hdr + CHK_OFF, CHK_LEN);
    if (stored == 0) return false;
    return stored == unsigned_sum || (int32_t)stored == signed_sum;
}

bool TARParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    if (offset + 512 > blob.size()) return false;
    const uint8_t* hdr = &blob[offset];

    // POSIX ustar magic at offset 257. Also accept a zero magic (old v7 tar)
    // only if the rest of the header is otherwise plausible — but for safety
    // against false positives in binary data, require ustar here.
    if (std::memcmp(hdr + 257, "ustar", 5) != 0) return false;

    // Typeflag must be a defined value.
    if (!isKnownTarTypeflag(hdr[156])) return false;

    // Checksum over the whole header — this is the real discriminator.
    return tarChecksumMatches(hdr);
}

ScanResult TARParser::parse(const std::vector<std::uint8_t>& blob, size_t offset) {
    ScanResult root;
    root.offset = offset;
    root.type = "TAR";
    root.extractorType = root.type;
    root.info = "POSIX tar archive";

    size_t pos = offset;
    while (pos + 512 <= blob.size()) {
        const uint8_t* hdr = &blob[pos];

        // End of archive: two consecutive zero blocks
        bool allzero = true;
        for (size_t i = 0; i < 512; i++) {
            if (hdr[i] != 0) { allzero = false; break; }
        }
        if (allzero) {
            // Consume both zero blocks
            pos += 1024;
            break;
        }

        std::string name = read_string(hdr, 100);
        size_t size = read_octal(hdr + 124, 12);
        char typeflag = hdr[156];

        /*ScanResult entry;
        entry.offset = pos;
        entry.type = (typeflag == '5') ? "Directory" :
                     (typeflag == '2') ? "Symlink" :
                     "File";
        entry.length = size;
        entry.info = name;
        entry.isValid = true;

        root.children.push_back(entry);*/

        // Advance to next header: header + padded data
        size_t blocks = (size + 511) / 512;
        pos += 512 + blocks * 512;
    }

    root.length = pos - offset;
    if(root.length > 0)
    {
        root.isValid = true;
    }
    return root;
}
REGISTER_PARSER(TARParser)