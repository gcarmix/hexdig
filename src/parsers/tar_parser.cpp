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

bool TARParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    if (offset + 512 > blob.size()) return false;
    const char* magic = reinterpret_cast<const char*>(&blob[offset + 257]);
    return (std::strncmp(magic, "ustar", 5) == 0);
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