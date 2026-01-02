#include "parser_registration.hpp"
#include "crc.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include <algorithm>

struct CRCMatch {
    std::string width;      // "CRC8" / "CRC16" / "CRC32"
    std::string polyName;   // e.g., "CRC-32/IEEE"
    uint64_t polynomial;    // polynomial value
    std::string endianness; // "LE" / "BE" / "byte-array"
    std::string confidence; // "high"
    size_t tableBytes;      // 256, 512, 1024
};

static bool compareFirst16(const std::vector<uint8_t>& blob, size_t off, const uint8_t* table) {
    if (off + 16 > blob.size()) return false;
    return std::equal(table, table + 16, blob.begin() + off);
}

static bool identifyCRC(const std::vector<uint8_t>& blob, size_t off, CRCMatch& out) {
    // CRC32 IEEE reflected
    if (compareFirst16(blob, off, CRC32_IEEE_REF_LE)) {
        out = {"CRC32", "CRC-32/IEEE (poly 0x04C11DB7)", 0x04C11DB7u, "LE", "high", 256*4};
        return true;
    }
    if (compareFirst16(blob, off, CRC32_IEEE_REF_BE)) {
        out = {"CRC32", "CRC-32/IEEE (poly 0x04C11DB7)", 0x04C11DB7u, "BE", "high", 256*4};
        return true;
    }

    // CRC16 IBM
    if (compareFirst16(blob, off, CRC16_IBM_REF_LE)) {
        out = {"CRC16", "CRC-16/IBM (poly 0x8005)", 0x8005, "LE", "high", 256*2};
        return true;
    }
    if (compareFirst16(blob, off, CRC16_IBM_REF_BE)) {
        out = {"CRC16", "CRC-16/IBM (poly 0x8005)", 0x8005, "BE", "high", 256*2};
        return true;
    }

    // CRC16 CCITT
    if (compareFirst16(blob, off, CRC16_CCITT_REF_LE)) {
        out = {"CRC16", "CRC-16/CCITT (poly 0x1021)", 0x1021, "LE", "high", 256*2};
        return true;
    }
    if (compareFirst16(blob, off, CRC16_CCITT_REF_BE)) {
        out = {"CRC16", "CRC-16/CCITT (poly 0x1021)", 0x1021, "BE", "high", 256*2};
        return true;
    }

    // CRC8
    if (compareFirst16(blob, off, CRC8_POLY07_REF)) {
        out = {"CRC8", "CRC-8 (poly 0x07)", 0x07, "byte-array", "high", 256};
        return true;
    }

    return false;
}

class CRCParser : public BaseParser {
public:
    std::string name() const override { return "CRC"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        CRCMatch m;
        return identifyCRC(blob, offset, m);
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "CRC"; // always "CRC"
        r.isValid = true;

        CRCMatch m;
        if (!identifyCRC(blob, offset, m)) {
            r.length = 0;
            r.info = "No CRC table recognized";
            return r;
        }

        r.length = m.tableBytes;
        std::ostringstream info;
        info << m.width << ", " << m.polyName
             << ", polynomial=0x" << std::hex << m.polynomial << std::dec
             << ", storage endianness=" << m.endianness
             << ", confidence=" << m.confidence
             << ", entries=256, table bytes=" << m.tableBytes;
        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(CRCParser)

