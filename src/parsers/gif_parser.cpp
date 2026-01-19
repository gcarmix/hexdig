#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <tuple>
#include <string>
#include <sstream>
#include "helpers.hpp"
class GIFParser : public BaseParser {
public:
    std::string name() const override { return "GIF"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        return offset + 6 <= blob.size() &&
               blob[offset] == 'G' && blob[offset+1] == 'I' && blob[offset+2] == 'F' &&
               blob[offset+3] == '8' && (blob[offset+4] == '7' || blob[offset+4] == '9') &&
               blob[offset+5] == 'a';
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "GIF";
        r.extractorType = "RAW";
        r.isValid = false;
        r.length = 0;

        // Header + Logical Screen Descriptor
        if (offset + 10 > blob.size()) {
            r.length = blob.size() - offset;
            r.info = "Truncated GIF header";
            return r;
        }

        const bool is89a = blob[offset+4] == '9';
        uint16_t width  = blob[offset + 6] | (blob[offset + 7] << 8);
        uint16_t height = blob[offset + 8] | (blob[offset + 9] << 8);

        size_t cursor = offset + 10;

        // Global Color Table
        uint8_t packed = blob[offset + 10 - 1]; // LSD packed at byte 10-1
        bool hasGCT = (packed & 0x80) != 0;
        if (hasGCT) {
            uint8_t gctSizeLog2 = (packed & 0x07);
            size_t gctEntries = 1u << (gctSizeLog2 + 1); // 2^(N+1)
            size_t gctBytes = gctEntries * 3;
            if (cursor + gctBytes > blob.size()) {
                r.length = blob.size() - offset;
                r.info = "Truncated Global Color Table";
                return r;
            }
            cursor += gctBytes;
        }

        // Block parsing loop
        auto readSubBlocks = [&](size_t& cur) -> bool {
            while (true) {
                if (cur >= blob.size()) return false;
                uint8_t sz = blob[cur++];
                if (sz == 0x00) return true; // terminator
                if (cur + sz > blob.size()) return false;
                cur += sz;
            }
        };

        while (cursor < blob.size()) {
            uint8_t marker = blob[cursor++];

            if (marker == 0x3B) { // Trailer — only valid here
                r.isValid = true;
                r.length = cursor - offset;
                std::ostringstream info;
                info << "Version: GIF" << (is89a ? "89a" : "87a")
                     << ", Resolution: " << width << "x" << height;
                r.info = info.str();
                return r;
            }

            if (marker == 0x2C) {
                // Image Descriptor: 9 bytes
                if (cursor + 9 > blob.size()) {
                    r.length = blob.size() - offset;
                    r.info = "Truncated Image Descriptor";
                    return r;
                }
                // Skip descriptor
                uint8_t packedImg = blob[cursor + 8];
                cursor += 9;

                // Local Color Table
                bool hasLCT = (packedImg & 0x80) != 0;
                if (hasLCT) {
                    uint8_t lctSizeLog2 = (packedImg & 0x07);
                    size_t lctEntries = 1u << (lctSizeLog2 + 1);
                    size_t lctBytes = lctEntries * 3;
                    if (cursor + lctBytes > blob.size()) {
                        r.length = blob.size() - offset;
                        r.info = "Truncated Local Color Table";
                        return r;
                    }
                    cursor += lctBytes;
                }

                // LZW minimum code size
                if (cursor >= blob.size()) {
                    r.length = blob.size() - offset;
                    r.info = "Missing LZW minimum code size";
                    return r;
                }
                cursor++; // skip LZW min code size

                // Image data sub-blocks
                if (!readSubBlocks(cursor)) {
                    r.length = blob.size() - offset;
                    r.info = "Truncated image data sub-blocks";
                    return r;
                }
                continue;
            }

            if (marker == 0x21) {
                // Extension: label then sub-blocks
                if (cursor >= blob.size()) {
                    r.length = blob.size() - offset;
                    r.info = "Truncated extension label";
                    return r;
                }
                uint8_t label = blob[cursor++];

                // For GIF89a, some extensions have fixed headers before sub-blocks
                // But we can universally consume sub-blocks after the optional block size.
                // If the next byte is a block-size (common), consume sub-blocks:
                if (cursor >= blob.size()) {
                    r.length = blob.size() - offset;
                    r.info = "Truncated extension";
                    return r;
                }

                // Some extensions start with a data sub-block immediately (Graphic Control: size=4)
                // Read sub-blocks structurally
                if (!readSubBlocks(cursor)) {
                    r.length = blob.size() - offset;
                    r.info = "Truncated extension sub-blocks";
                    return r;
                }
                continue;
            }

            // Any other marker before trailer is invalid per spec
            r.length = cursor - offset;
            r.info = "Invalid block marker 0x" + to_hex(marker);
            return r;
        }

        // If we exit the loop without trailer, it's truncated
        r.length = blob.size() - offset;
        r.info = "Truncated: trailer not found";
        return r;
    }
};


REGISTER_PARSER(GIFParser)
