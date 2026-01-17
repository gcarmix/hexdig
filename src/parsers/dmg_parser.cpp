#include "parser_registration.hpp"
#include "scanner.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include "helpers.hpp"
#include "logger.hpp"



class DMGParser : public BaseParser {
public:
    std::string name() const override { return "DMG"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;
};

// Match only the UDIF footer signature at the given offset
bool DMGParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + 12 > blob.size())
        return false;

    // "koly"
    if (blob[offset]     != 0x6B ||
        blob[offset + 1] != 0x6F ||
        blob[offset + 2] != 0x6C ||
        blob[offset + 3] != 0x79)
        return false;

    uint32_t version    = read_be32(blob, offset + 4);
    uint32_t headerSize = read_be32(blob, offset + 8);

    // Version 4, header size 512
    if (version != 4)
        return false;
    if (headerSize != 512)
        return false;

    return true;
}

ScanResult DMGParser::parse(const std::vector<uint8_t>& blob, size_t trailerOffset) {
    ScanResult result;
    result.type = "DMG";
    result.extractorType = "7Z";
    result.offset = trailerOffset;
    result.length = 0;
    result.isValid = false;
    result.info = "Invalid DMG";

    if (trailerOffset + 512 > blob.size())
        return result;

    const size_t base = trailerOffset;

    // UDIFResourceFile layout (offsets from start of trailer)
    uint32_t signature   = read_be32(blob, base + 0x00); // 'koly'
    uint32_t version     = read_be32(blob, base + 0x04);
    uint32_t headerSize  = read_be32(blob, base + 0x08);
    uint32_t flags       = read_be32(blob, base + 0x0C);

    uint64_t runningDataForkOffset = read_be64(blob, base + 0x10);
    uint64_t dataForkOffset        = read_be64(blob, base + 0x18);
    uint64_t dataForkLength        = read_be64(blob, base + 0x20);
    uint64_t rsrcForkOffset        = read_be64(blob, base + 0x28);
    uint64_t rsrcForkLength        = read_be64(blob, base + 0x30);

    uint32_t segmentNumber = read_be32(blob, base + 0x38);
    uint32_t segmentCount  = read_be32(blob, base + 0x3C);
    // SegmentID at 0x40 (16 bytes) – skip for now

    uint32_t dataChecksumType = read_be32(blob, base + 0x50);
    uint32_t dataChecksumSize = read_be32(blob, base + 0x54);
    // DataChecksum[32] at 0x58 – skip contents

    uint64_t xmlOffset  = read_be64(blob, base + 0xD8);
    uint64_t xmlLength  = read_be64(blob, base + 0xE0);

    uint32_t checksumType = read_be32(blob, base + 0x160);
    uint32_t checksumSize = read_be32(blob, base + 0x164);
    // Checksum[32] at 0x168 – skip contents

    uint32_t imageVariant = read_be32(blob, base + 0x1E8);
    uint64_t sectorCount  = read_be64(blob, base + 0x1EC);
    uint32_t reserved2    = read_be32(blob, base + 0x1F4);
    uint32_t reserved3    = read_be32(blob, base + 0x1F8);
    uint32_t reserved4    = read_be32(blob, base + 0x1FC);

    // Basic sanity
    if (signature != 0x6B6F6C79) // 'koly'
        return result;
    if (version != 4)
        return result;
    if (headerSize != 512)
        return result;

    // Determine if this looks like a whole-file DMG:
    // trailer is exactly the last 512 bytes of the blob
    bool wholeFile = (trailerOffset + 512 == blob.size());

    uint64_t dmgStart = 0;
    uint64_t dmgSize  = 0;

    if (wholeFile) {
        // For a full DMG file, the DMG starts at 0 and ends at EOF.
        dmgStart = 0;
        dmgSize  = blob.size();
    } else {
        // Embedded DMG: estimate size from fork and XML ranges.
        uint64_t maxEnd = 0;

        if (dataForkLength > 0)
            maxEnd = std::max(maxEnd, dataForkOffset + dataForkLength);
        if (rsrcForkLength > 0)
            maxEnd = std::max(maxEnd, rsrcForkOffset + rsrcForkLength);
        if (xmlLength > 0)
            maxEnd = std::max(maxEnd, xmlOffset + xmlLength);

        if (maxEnd == 0)
            return result;

        dmgSize = maxEnd + 512; // include trailer
        uint64_t dmgEnd = (uint64_t)trailerOffset + 512;
        if (dmgEnd < dmgSize)
            return result;

        dmgStart = dmgEnd - dmgSize;

        if (dmgStart + dmgSize > blob.size())
            return result;
    }

    // Optional: sanity-check that forks (if present) lie within [dmgStart, dmgStart + dmgSize]
    uint64_t dmgEndAbs = dmgStart + dmgSize;

    if (dataForkLength > 0) {
        uint64_t absDataStart = dmgStart + dataForkOffset;
        uint64_t absDataEnd   = absDataStart + dataForkLength;
        if (absDataStart < dmgStart || absDataEnd > dmgEndAbs)
            return result;
    }

    if (rsrcForkLength > 0) {
        uint64_t absRsrcStart = dmgStart + rsrcForkOffset;
        uint64_t absRsrcEnd   = absRsrcStart + rsrcForkLength;
        if (absRsrcStart < dmgStart || absRsrcEnd > dmgEndAbs)
            return result;
    }

    // Looks good
    result.offset  = (size_t)dmgStart;
    result.length  = (size_t)dmgSize;
    result.isValid = true;

    std::ostringstream info;
    info << "Apple UDIF disk image (DMG), version=" << version
         << ", headerSize=" << headerSize
         << ", flags=0x" << std::hex << flags << std::dec
         << ", dataForkOffset=" << dataForkOffset
         << ", dataForkLength=" << dataForkLength
         << ", rsrcForkOffset=" << rsrcForkOffset
         << ", rsrcForkLength=" << rsrcForkLength
         << ", xmlOffset=" << xmlOffset
         << ", xmlLength=" << xmlLength
         << ", imageVariant=" << imageVariant
         << ", sectorCount=" << sectorCount
         << ", wholeFile=" << (wholeFile ? "true" : "false");

    result.info = info.str();
    return result;
}

REGISTER_PARSER(DMGParser)
