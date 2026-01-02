#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
class RomfsParser : public BaseParser {
public:
    std::string name() const override { return "ROMFS"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 8 > blob.size()) return false;
        std::string sig = "-rom1fs-";
        for (int i=0;i<8;i++) {
            if (blob[offset+i] != (uint8_t)sig.at(i)) return false;
        }
        return true;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "ROMFS";
        r.extractorType = "ROMFS";
        r.isValid = false;
        r.length = 0;

        if (offset + 16 > blob.size()) {
            r.info = "Truncated ROMFS superblock";
            r.length = blob.size() - offset;
            return r;
        }

        uint32_t fsSize   = read_be32(blob, offset + 8);
        uint32_t checksum = read_be32(blob, offset + 12);

        size_t available = blob.size() - offset;
        size_t computedLen = std::min<size_t>(fsSize, available);

        r.length = computedLen;
        r.isValid = (fsSize > 0 && fsSize <= available);

        std::ostringstream info;
        info << "ROMFS filesystem, size=" << fsSize
             << " bytes, checksum=0x" << std::hex << checksum << std::dec;
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(RomfsParser)
