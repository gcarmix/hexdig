#include "base_parser.hpp"
#include "cpio_extractor.cpp"
#include "parser_registration.hpp"
#include <cstring>
#include <sstream>
#include "logger.hpp"

class CPIOParser : public BaseParser {
public:
    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override;
    std::string name() const override { return "CPIO"; }
};

static bool is_cpio_magic(const std::vector<uint8_t>& blob, size_t offset) {
    return offset + 6 <= blob.size() &&
           std::memcmp(&blob[offset], "070701", 6) == 0;
}

bool CPIOParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    return is_cpio_magic(blob, offset);
}

ScanResult CPIOParser::parse(const std::vector<std::uint8_t>& blob, size_t offset) {
    ScanResult result;
    result.offset = offset;
    result.type = name();
    result.extractorType = result.type;
    result.info = "CPIO archive";
    result.isValid = true;
    size_t pos = offset;
    while (pos + 110 < blob.size()) {
        if (!is_cpio_magic(blob, pos)) break;

        std::string name(reinterpret_cast<const char*>(&blob[pos + 110]), 10);
        if (name.find("TRAILER!!!") != std::string::npos) {
            result.length = (pos + 110 + 10 + 3) & ~3;  // pad to 4 bytes
            return result;
        }

        // Read file name size and file size
        std::string namesize_str(reinterpret_cast<const char*>(&blob[pos + 94]), 8);
        std::string filesize_str(reinterpret_cast<const char*>(&blob[pos + 54]), 8);
        if (namesize_str.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos ||
            filesize_str.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            result.isValid = false;
            return result;
        }
        size_t namesize = std::stoul(namesize_str, nullptr, 16);
        size_t filesize = std::stoul(filesize_str, nullptr, 16);

        size_t header_end = pos + 110;
        size_t name_end = (header_end + namesize + 3) & ~3;
        size_t file_end = (name_end + filesize + 3) & ~3;

        if (file_end > blob.size()) break;
        pos = file_end;
    }

    result.isValid = false;
    result.info += ", malformed or truncated";
    return result;
}



REGISTER_PARSER(CPIOParser)