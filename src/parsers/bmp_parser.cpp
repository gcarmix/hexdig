#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"



class BMPParser : public BaseParser {
public:
    std::string name() const override { return "BMP"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 2 > blob.size()) return false;
        return blob[offset] == 'B' && blob[offset+1] == 'M';
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "BMP";
        r.extractorType = "RAW";
        r.isValid = false;
        r.length = 0;

        if (offset + 54 > blob.size()) { // minimal header size
            r.info = "Truncated BMP header";
            r.length = blob.size() - offset;
            return r;
        }

        // File header
        uint32_t fileSize   = read_le32(blob, offset + 2);
        uint32_t dataOffset = read_le32(blob, offset + 10);

        // DIB header (BITMAPINFOHEADER)
        uint32_t dibSize = read_le32(blob, offset + 14);
        int32_t width    = (int32_t)read_le32(blob, offset + 18);
        int32_t height   = (int32_t)read_le32(blob, offset + 22);
        uint16_t planes  = read_le16(blob, offset + 26);
        uint16_t bpp     = read_le16(blob, offset + 28);
        uint32_t comp    = read_le32(blob, offset + 30);
        uint32_t imgSize = read_le32(blob, offset + 34);

        // Validate
        bool plausible = (planes == 1) && (bpp > 0 && bpp <= 64);
        size_t available = blob.size() - offset;
        size_t computedLen = std::min<size_t>(fileSize, available);

        r.length = computedLen;
        r.isValid = plausible;

        std::ostringstream info;
        info << "BMP image, " << width << "x" << height
             << ", bpp=" << bpp
             << ", compression=" << comp
             << ", fileSize=" << fileSize
             << ", dataOffset=" << dataOffset
             << ", DIB size=" << dibSize
             << ", imageSize=" << imgSize;
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(BMPParser)
