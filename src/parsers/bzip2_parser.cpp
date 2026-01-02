#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
// Helper

class Bzip2Parser : public BaseParser {
public:
    std::string name() const override { return "Bzip2"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 4 > blob.size()) return false;
        return blob[offset] == 'B' &&
               blob[offset+1] == 'Z' &&
               blob[offset+2] == 'h' &&
               (blob[offset+3] >= '1' && blob[offset+3] <= '9');
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "Bzip2";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 0;

        if (offset + 4 > blob.size()) {
            r.info = "Truncated Bzip2 header";
            r.length = blob.size() - offset;
            return r;
        }

        size_t cursor = offset;
        size_t memberCount = 0;
        size_t blockCountTotal = 0;
        bool allEndedProperly = true;

        while (cursor + 4 <= blob.size() &&
               blob[cursor] == 'B' && blob[cursor+1] == 'Z' &&
               blob[cursor+2] == 'h' && (blob[cursor+3] >= '1' && blob[cursor+3] <= '9')) {

            char blockSizeChar = (char)blob[cursor+3];
            int blockSize100k = blockSizeChar - '0';

            cursor += 4; // skip header
            size_t blockCount = 0;
            bool endFound = false;

            while (cursor + 6 <= blob.size()) {
                uint32_t marker = read_be32(blob, cursor);
                uint16_t marker2 = read_be16(blob, cursor+4);

                if (marker == 0x31415926 && marker2 == 0x5359) {
                    // Block header
                    blockCount++;
                    cursor += 6;
                    // Skip until next marker (heuristic)
                    size_t next = findNextMarker(blob, cursor);
                    if (next == blob.size()) { cursor = next; break; }
                    cursor = next;
                } else if (marker == 0x17724538 && marker2 == 0x5090) {
                    // End marker
                    endFound = true;
                    cursor += 6;
                    break;
                } else {
                    break;
                }
            }

            memberCount++;
            blockCountTotal += blockCount;
            if (!endFound) allEndedProperly = false;
        }

        size_t available = blob.size() - offset;
        r.length = std::min(cursor - offset, available);
        r.isValid = (memberCount > 0);

        std::ostringstream info;
        info << "Bzip2 archive, members=" << memberCount
             << ", total blocks=" << blockCountTotal
             << (allEndedProperly ? ", all end markers OK" : ", some members truncated/missing end marker");
        r.info = info.str();

        return r;
    }

private:
    size_t findNextMarker(const std::vector<uint8_t>& blob, size_t start) {
        for (size_t i = start; i + 6 <= blob.size(); ++i) {
            uint32_t m = read_be32(blob, i);
            uint16_t m2 = read_be16(blob, i+4);
            if ((m == 0x31415926 && m2 == 0x5359) ||
                (m == 0x17724538 && m2 == 0x5090)) {
                return i;
            }
        }
        return blob.size();
    }
};

REGISTER_PARSER(Bzip2Parser)
