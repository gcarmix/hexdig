#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <tuple>

class PDFParser : public BaseParser {
public:
    std::string name() const override { return "PDF"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    std::string extractVersion(const std::vector<uint8_t>& blob, size_t offset);
    size_t findLastEOF(const std::vector<uint8_t>& blob, size_t offset);
};


bool PDFParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    const char* magic = "%PDF-";
    return offset + 5 < blob.size() &&
           std::memcmp(&blob[offset], magic, 5) == 0;
}

ScanResult PDFParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    std::string version = extractVersion(blob, offset);
    size_t end = findLastEOF(blob, offset);
    size_t length = end > offset ? end - offset : blob.size() - offset;

    std::ostringstream info;
    info << "Version: " << version;
    ScanResult result;
    result.offset = offset;
    result.type = "PDF";
    result.length = length;
    result.isValid = true;
    result.info = info.str();
    return result;
}

std::string PDFParser::extractVersion(const std::vector<uint8_t>& blob, size_t offset) {
    std::string version = "unknown";
    if (offset + 8 < blob.size()) {
        version = std::string(blob.begin() + offset + 5, blob.begin() + offset + 8);
    }
    return version;
}

size_t PDFParser::findLastEOF(const std::vector<uint8_t>& blob, size_t offset) {
    const char* eof_marker = "%%EOF";
    size_t last_eof = offset;

    for (size_t i = offset; i + 5 < blob.size(); ++i) {
        if (std::memcmp(&blob[i], eof_marker, 5) == 0) {
            last_eof = i + 5;
        }
    }

    return last_eof;
}

REGISTER_PARSER(PDFParser)