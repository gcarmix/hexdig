#include "parser_registration.hpp"
#include <tuple>
#include <string>
#include <sstream>
#include <iomanip>

class JPGParser : public BaseParser {
public:
    std::string name() const override { return "JPG"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    bool findSOF(const std::vector<uint8_t>& blob, size_t start, size_t& width, size_t& height);
};


bool JPGParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    // JPEG magic: FF D8
    return offset + 1 < blob.size() &&
           blob[offset] == 0xFF &&
           blob[offset + 1] == 0xD8 && 
           blob[offset + 2] == 0xFF &&
           (blob[offset + 3] == 0xE0 || blob[offset + 3] == 0xE1 ||blob[offset + 3] == 0xDB);
}

ScanResult JPGParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    size_t length = 0;
    size_t width = 0, height = 0;
    size_t i = offset + 2;

    bool foundEnd = false;
    bool foundSOF = false;

    while (i + 1 < blob.size()) {
        if (blob[i] != 0xFF) {
            ++i;
            continue;
        }

        uint8_t marker = blob[i + 1];

        // End of image marker
        if (marker == 0xD9) {
            length = i + 2 - offset;
            foundEnd = true;
            break;
        }

        // Skip padding FFs
        if (marker == 0xFF) {
            ++i;
            continue;
        }

        // Restart markers (0xD0–0xD7) have no length
        if (marker >= 0xD0 && marker <= 0xD7) {
            i += 2;
            continue;
        }

        // Check segment length
        if (i + 4 > blob.size()) break;
        uint16_t segment_length = (blob[i + 2] << 8) | blob[i + 3];
        if (segment_length < 2 || i + 2 + segment_length > blob.size()) break;

        // SOF0–SOF3: extract dimensions
        if (!foundSOF && (marker >= 0xC0 && marker <= 0xC3)) {
            if (segment_length < 7) break; // Not enough bytes for SOF
            height = static_cast<size_t>((blob[i + 5] << 8) | blob[i + 6]);
            width  = static_cast<size_t>((blob[i + 7] << 8) | blob[i + 8]);
            foundSOF = true;
        }

        i += 2 + segment_length;
    }

    if (!foundEnd) length = blob.size() - offset;

    std::ostringstream info;
    info << "Resolution: " << width << "x" << height;
    ScanResult result;
    result.offset = offset;
    result.type = "JPG";
    result.extractorType = "RAW";
    result.info = info.str();
    result.length = length;
    result.isValid = true;
    return result;
}

REGISTER_PARSER(JPGParser)