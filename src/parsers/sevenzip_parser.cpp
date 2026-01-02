#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
#include "logger.hpp"

class SevenZipParser : public BaseParser {
public:
    std::string name() const override { return "7Z"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 6 > blob.size()) return false;
        static const uint8_t sig[6] = {0x37,0x7A,0xBC,0xAF,0x27,0x1C};
        for (int i=0;i<6;i++) {
            if (blob[offset+i] != sig[i]) return false;
        }
        return true;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "7Z";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 0;

        if (offset + 32 > blob.size()) {
            r.info = "Truncated 7-Zip header";
            r.length = blob.size() - offset;
            return r;
        }

        uint16_t version = read_le16(blob, offset + 6);
        uint32_t startHeaderCRC = read_le32(blob, offset + 8);
        uint64_t nextHeaderOffset = read_le64(blob, offset + 12);
        uint64_t nextHeaderSize   = read_le64(blob, offset + 20);
        uint32_t nextHeaderCRC    = read_le32(blob, offset + 28);

        // Validate plausibility
        bool plausible = (version > 0) &&
                         (nextHeaderSize < blob.size());

        size_t available = blob.size() - offset;
        size_t computedLen = std::min<size_t>(offset + 32 + nextHeaderOffset + nextHeaderSize, blob.size()) - offset;

        r.length = computedLen;
        r.isValid = plausible;

        std::ostringstream info;
        info << "7-Zip archive, version=" << ((version>>8)&0xFF) << "." << (version&0xFF)
             << ", nextHeaderSize=" << nextHeaderSize
             << ", offset=" << nextHeaderOffset
             << ", CRCs: start=0x" << std::hex << startHeaderCRC
             << ", next=0x" << nextHeaderCRC << std::dec;
        r.info = info.str();
        Logger::debug(r.info);
        return r;
    }
};

REGISTER_PARSER(SevenZipParser)
