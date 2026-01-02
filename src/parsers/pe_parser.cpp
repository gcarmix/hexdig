#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <tuple>

class PEParser : public BaseParser {
public:
    std::string name() const override { return "EXE"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    bool isValidPE(const std::vector<uint8_t>& blob, size_t offset, size_t& peOffset, std::string& arch);
    size_t estimateLength(const std::vector<uint8_t>& blob, size_t peOffset);
};


bool PEParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    return offset + 2 < blob.size() &&
           blob[offset] == 'M' &&
           blob[offset + 1] == 'Z';
}

ScanResult PEParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    size_t peOffset = 0;
    std::string arch = "unknown";
    ScanResult result;
    result.offset = offset;
    result.type = "EXE";

    if (!isValidPE(blob, offset, peOffset, arch)) {
        result.info = "Invalid PE Header";
        return result;
    }

    result.length = estimateLength(blob, peOffset);

    result.isValid = true;
    result.info = "PE32, Arch: " + arch;

    return result;
}

bool PEParser::isValidPE(const std::vector<uint8_t>& blob, size_t offset, size_t& peOffset, std::string& arch) {
    if (offset + 0x3C + 4 > blob.size()) return false;

    peOffset = static_cast<size_t>(
        blob[offset + 0x3C] |
        (blob[offset + 0x3D] << 8) |
        (blob[offset + 0x3E] << 16) |
        (blob[offset + 0x3F] << 24)
    );

    if (offset + peOffset + 6 > blob.size()) return false;

    if (blob[offset + peOffset] != 'P' || blob[offset + peOffset + 1] != 'E') return false;

    uint16_t machine = blob[offset + peOffset + 4] | (blob[offset + peOffset + 5] << 8);
    switch (machine) {
        case 0x014C: arch = "x86"; break;
        case 0x8664: arch = "x64"; break;
        default: arch = "unknown"; break;
    }

    return true;
}

size_t PEParser::estimateLength(const std::vector<uint8_t>& blob, size_t peOffset) {
    // Heuristic: scan for next MZ or end of blob
    for (size_t i = peOffset + 4; i + 1 < blob.size(); ++i) {
        if (blob[i] == 'M' && blob[i + 1] == 'Z') {
            return i - peOffset;
        }
    }
    return blob.size() - peOffset;
}

REGISTER_PARSER(PEParser)