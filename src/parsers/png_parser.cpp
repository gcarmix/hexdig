#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <tuple>

class PNGParser : public BaseParser {
public:
    std::string name() const override { return "PNG"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    bool extractIHDR(const std::vector<uint8_t>& blob, size_t offset, size_t& width, size_t& height);
    size_t findIEND(const std::vector<uint8_t>& blob, size_t offset);
};

bool PNGParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    const uint8_t png_magic[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    return offset + 8 <= blob.size() &&
           std::memcmp(&blob[offset], png_magic, 8) == 0;
}

ScanResult PNGParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    size_t width = 0, height = 0;
    extractIHDR(blob, offset, width, height);

    size_t end = findIEND(blob, offset);
    size_t length = end > offset ? end - offset : blob.size() - offset;

    std::ostringstream info;
    info << "Resolution: " << width << "x" << height;
    ScanResult result;
     result.type = "PNG";
        result.length = length;
        result.offset = offset;
        result.isValid = true;
        result.info = info.str();
        return result;
}

bool PNGParser::extractIHDR(const std::vector<uint8_t>& blob, size_t offset, size_t& width, size_t& height) {
    size_t ihdr_offset = offset + 8;
    if (ihdr_offset + 25 > blob.size()) return false;

    // IHDR chunk starts with 4-byte length, then "IHDR"
    if (std::memcmp(&blob[ihdr_offset + 4], "IHDR", 4) != 0) return false;

    width = (blob[ihdr_offset + 8] << 24) |
            (blob[ihdr_offset + 9] << 16) |
            (blob[ihdr_offset + 10] << 8) |
            blob[ihdr_offset + 11];

    height = (blob[ihdr_offset + 12] << 24) |
             (blob[ihdr_offset + 13] << 16) |
             (blob[ihdr_offset + 14] << 8) |
             blob[ihdr_offset + 15];

    return true;
}

size_t PNGParser::findIEND(const std::vector<uint8_t>& blob, size_t offset) {
    const char* iend_sig = "IEND";
    for (size_t i = offset + 8; i + 7 < blob.size(); ++i) {
        if (std::memcmp(&blob[i + 4], iend_sig, 4) == 0) {
            return i + 12; // 4-byte length + 4-byte type + 4-byte CRC
        }
    }
    return blob.size();
}

REGISTER_PARSER(PNGParser)