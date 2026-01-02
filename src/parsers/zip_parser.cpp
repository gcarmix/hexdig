#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <tuple>
#include "scanner.hpp"
class ZIPParser : public BaseParser {
public:
    std::string name() const override { return "ZIP"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    size_t findEndOfCentralDirectory(const std::vector<uint8_t>& blob, size_t offset);
    uint16_t extractFileCount(const std::vector<uint8_t>& blob, size_t eocdOffset);
};

bool ZIPParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    return offset + 3 < blob.size() &&
           blob[offset] == 0x50 &&
           blob[offset + 1] == 0x4B &&
           (blob[offset + 2] == 0x03 || blob[offset + 2] == 0x05 || blob[offset + 2] == 0x07) &&
           (blob[offset + 3] == 0x04 || blob[offset + 3] == 0x06 || blob[offset + 3] == 0x08);
}

ScanResult ZIPParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    size_t eocdOffset = findEndOfCentralDirectory(blob, offset);
    size_t length = eocdOffset > offset ? eocdOffset - offset : blob.size() - offset;
    uint16_t count = extractFileCount(blob, eocdOffset);

    std::ostringstream info;
    info << "Central Dir: " << count << " file(s)";
    ScanResult result;
     result.type = "ZIP";
     result.extractorType = result.type;
        result.length = length;
        result.offset = offset;
        result.isValid = true;
        result.info = info.str();
        return result;

}

size_t ZIPParser::findEndOfCentralDirectory(const std::vector<uint8_t>& blob, size_t offset) {
    const char* eocd_sig = "\x50\x4B\x05\x06";
    for (size_t i = blob.size() - 22; i > offset && i + 4 < blob.size(); --i) {
        if (std::memcmp(&blob[i], eocd_sig, 4) == 0) {
            return i + 22;
        }
    }
    return blob.size();
}

uint16_t ZIPParser::extractFileCount(const std::vector<uint8_t>& blob, size_t eocdOffset) {
    if (eocdOffset < 22 || eocdOffset > blob.size()) return 0;
    return blob[eocdOffset - 6] | (blob[eocdOffset - 5] << 8);
}




REGISTER_PARSER(ZIPParser)