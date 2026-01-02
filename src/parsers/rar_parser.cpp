#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
class RARParser : public BaseParser {
public:
    std::string name() const override { return "RAR"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 7 > blob.size()) return false;
        // RAR 4.x signature
        static const uint8_t sig4[7] = {0x52,0x61,0x72,0x21,0x1A,0x07,0x00};
        // RAR 5.x signature
        static const uint8_t sig5[8] = {0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00};

        bool match4 = true;
        for (int i=0;i<7;i++) if (blob[offset+i] != sig4[i]) match4=false;
        bool match5 = true;
        if (offset + 8 <= blob.size()) {
            for (int i=0;i<8;i++) if (blob[offset+i] != sig5[i]) match5=false;
        } else match5=false;

        return match4 || match5;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "RAR";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 0;

        if (offset + 7 > blob.size()) {
            r.info = "Truncated RAR header";
            r.length = blob.size() - offset;
            return r;
        }

        bool isRAR5 = false;
        if (offset + 8 <= blob.size() &&
            blob[offset+0]==0x52 && blob[offset+1]==0x61 &&
            blob[offset+2]==0x72 && blob[offset+3]==0x21 &&
            blob[offset+4]==0x1A && blob[offset+5]==0x07 &&
            blob[offset+6]==0x01 && blob[offset+7]==0x00) {
            isRAR5 = true;
        }

        // Minimal plausibility: check header size field
        size_t cursor = offset + (isRAR5 ? 8 : 7);
        size_t blockCount = 0;
        while (cursor + 7 <= blob.size()) {
            // Each block has CRC (2 bytes), type (1 byte), flags (2 bytes), size (2 bytes)
            uint16_t crc = read_le16(blob, cursor);
            uint8_t type = blob[cursor+2];
            uint16_t flags = read_le16(blob, cursor+3);
            uint16_t size  = read_le16(blob, cursor+5);

            if (size < 7 || cursor + size > blob.size()) break;
            blockCount++;
            cursor += size;

            // End of archive marker (type==0x7B in RAR4)
            if (!isRAR5 && type == 0x7B) break;
            // In RAR5, blocks are variable; we stop when we can't parse further
        }

        size_t available = blob.size() - offset;
        r.length = std::min(cursor - offset, available);
        r.isValid = (blockCount > 0);

        std::ostringstream info;
        info << "RAR archive, format=" << (isRAR5 ? "RAR5" : "RAR4")
             << ", blocks=" << blockCount;
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(RARParser)
