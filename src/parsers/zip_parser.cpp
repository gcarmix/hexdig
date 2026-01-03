#include "parser_registration.hpp"
#include "scanner.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

class ZIPParser : public BaseParser {
public:
    std::string name() const override { return "ZIP"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    size_t findEndOfCentralDirectory(const std::vector<uint8_t>& blob, size_t zipBase);
    uint16_t extractFileCount(const std::vector<uint8_t>& blob, size_t eocdEnd);
    bool validateCRCForSomeEntries(const std::vector<uint8_t>& blob,
                                   size_t zipBase,
                                   size_t cdStart,
                                   size_t cdEnd,
                                   unsigned maxEntriesToCheck = 5);
    bool validateCRCEntry(const std::vector<uint8_t>& blob,
                          size_t zipBase,
                          size_t cdEntryOffset);
};

bool ZIPParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    // Local file header signatures: PK 03 04, PK 05 06, PK 07 08
    if (offset + 4 > blob.size()) return false;

    if (blob[offset] != 0x50 || blob[offset + 1] != 0x4B)
        return false;

    uint8_t b2 = blob[offset + 2];
    uint8_t b3 = blob[offset + 3];

    if ((b2 == 0x03 && b3 == 0x04) || // local file header
        (b2 == 0x05 && b3 == 0x06) || // EOCD (rare starting point)
        (b2 == 0x07 && b3 == 0x08))   // data descriptor
    {
        return true;
    }

    return false;
}

ScanResult ZIPParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    ScanResult result;
    result.type = "ZIP";
    result.extractorType = "7Z";
    result.offset = offset;
    result.length = 0;
    result.isValid = false;
    result.info = "";

    if (offset >= blob.size()) {
        result.info = "Offset beyond blob size";
        return result;
    }

    size_t eocdEnd = findEndOfCentralDirectory(blob, offset);
    if (eocdEnd <= offset || eocdEnd > blob.size()) {
        // No EOCD found that structurally matches this ZIP start
        result.info = "No valid EOCD found for ZIP at offset";
        return result;
    }

    size_t length = eocdEnd - offset;
    uint16_t count = extractFileCount(blob, eocdEnd);

    std::ostringstream info;
    info << "ZIP archive, files=" << count << ", size=" << length << " bytes";

    result.length = length;
    result.isValid = true;
    result.info = info.str();

    return result;
}

// Forward search for EOCD starting from zipBase.
// EOCD signature: 50 4B 05 06
// EOCD must be within maxSearch bytes of zipBase; we verify central directory
// location and optionally CRC consistency to avoid false positives.
size_t ZIPParser::findEndOfCentralDirectory(const std::vector<uint8_t>& blob, size_t zipBase) {
    const uint8_t sig[4] = {0x50, 0x4B, 0x05, 0x06};

    if (blob.size() < zipBase + 22)
        return blob.size();

    size_t searchEnd = blob.size();
    for (size_t i = zipBase; i + 22 <= searchEnd; ++i) {
        if (blob[i + 0] == sig[0] &&
            blob[i + 1] == sig[1] &&
            blob[i + 2] == sig[2] &&
            blob[i + 3] == sig[3]) {

            // We found EOCD signature candidate.
            if (i + 22 > blob.size())
                continue;

            // Comment length at offset +20 (2 bytes, LE)
            uint16_t commentLen =
                (uint16_t)blob[i + 20] |
                ((uint16_t)blob[i + 21] << 8);

            size_t eocdEnd = i + 22 + commentLen;
            if (eocdEnd > blob.size())
                continue;

            // V2 (normal ZIP, no ZIP64):
            // size of central directory (4 bytes at offset +12)
            uint32_t sizeCD =
                (uint32_t)blob[i + 12]        |
                ((uint32_t)blob[i + 13] << 8) |
                ((uint32_t)blob[i + 14] << 16)|
                ((uint32_t)blob[i + 15] << 24);

            // offset of central directory (4 bytes at offset +16), relative to zipBase
            uint32_t offCD =
                (uint32_t)blob[i + 16]        |
                ((uint32_t)blob[i + 17] << 8) |
                ((uint32_t)blob[i + 18] << 16)|
                ((uint32_t)blob[i + 19] << 24);

            size_t cdStart = zipBase + offCD;
            size_t cdEnd   = cdStart + sizeCD;

            // Structural sanity checks for central directory region
            if (cdStart < zipBase)      continue;
            if (cdEnd   > i)            continue; // CD must be entirely before EOCD
            if (cdEnd   > blob.size())  continue;

            // Optional but strong: validate a few CD entries' CRC consistency
            if (!validateCRCForSomeEntries(blob, zipBase, cdStart, cdEnd)) {
                continue;
            }

            // If we get here, EOCD + CD look structurally consistent for this zipBase
            return eocdEnd;
        }
    }

    // No valid EOCD found
    return blob.size();
}

uint16_t ZIPParser::extractFileCount(const std::vector<uint8_t>& blob, size_t eocdEnd) {
    if (eocdEnd < 22 || eocdEnd > blob.size())
        return 0;

    // Comment length (last 2 bytes of EOCD header)
    uint16_t commentLen =
        (uint16_t)blob[eocdEnd - 2] |
        ((uint16_t)blob[eocdEnd - 1] << 8);

    if (eocdEnd < 22 + commentLen)
        return 0;

    size_t eocdStart = eocdEnd - 22 - commentLen;
    if (eocdStart + 22 > blob.size())
        return 0;

    // Total number of entries in the central directory (2 bytes at offset +10)
    uint16_t totalEntries =
        (uint16_t)blob[eocdStart + 10] |
        ((uint16_t)blob[eocdStart + 11] << 8);

    return totalEntries;
}

// Walk a few central directory entries and check CRC consistency between
// the central directory entry and the local file header.
// We don't need to check them all; a handful is enough to strongly confirm.
bool ZIPParser::validateCRCForSomeEntries(const std::vector<uint8_t>& blob,
                                          size_t zipBase,
                                          size_t cdStart,
                                          size_t cdEnd,
                                          unsigned maxEntriesToCheck)
{
    size_t pos = cdStart;
    unsigned checked = 0;
    unsigned valid = 0;

    while (pos + 46 <= cdEnd && checked < maxEntriesToCheck) {
        // Central directory header signature: 50 4B 01 02
        if (!(blob[pos + 0] == 0x50 &&
              blob[pos + 1] == 0x4B &&
              blob[pos + 2] == 0x01 &&
              blob[pos + 3] == 0x02)) {
            // Not a central directory header; break out
            break;
        }

        // filename length, extra length, comment length
        uint16_t nameLen =
            (uint16_t)blob[pos + 28] |
            ((uint16_t)blob[pos + 29] << 8);
        uint16_t extraLen =
            (uint16_t)blob[pos + 30] |
            ((uint16_t)blob[pos + 31] << 8);
        uint16_t commentLen =
            (uint16_t)blob[pos + 32] |
            ((uint16_t)blob[pos + 33] << 8);

        size_t entrySize = 46 + (size_t)nameLen + (size_t)extraLen + (size_t)commentLen;
        if (pos + entrySize > cdEnd) {
            break;
        }

        if (validateCRCEntry(blob, zipBase, pos))
            valid++;

        checked++;
        pos += entrySize;
    }

    // If we couldn't even parse one entry, be conservative
    if (checked == 0)
        return false;

    // Accept if at least one entry passes CRC consistency
    return (valid > 0);
}

// Validate a single central directory entry against its local file header CRC.
// This does NOT verify the actual data, only consistency between CD and LFH.
bool ZIPParser::validateCRCEntry(const std::vector<uint8_t>& blob,
                                 size_t zipBase,
                                 size_t cdEntryOffset)
{
    if (cdEntryOffset + 46 > blob.size())
        return false;

    // CRC from central directory (4 bytes at +16)
    uint32_t crcCentral =
        (uint32_t)blob[cdEntryOffset + 16]        |
        ((uint32_t)blob[cdEntryOffset + 17] << 8) |
        ((uint32_t)blob[cdEntryOffset + 18] << 16)|
        ((uint32_t)blob[cdEntryOffset + 19] << 24);

    // Relative offset of local header (4 bytes at +42)
    uint32_t localHeaderRel =
        (uint32_t)blob[cdEntryOffset + 42]        |
        ((uint32_t)blob[cdEntryOffset + 43] << 8) |
        ((uint32_t)blob[cdEntryOffset + 44] << 16)|
        ((uint32_t)blob[cdEntryOffset + 45] << 24);

    size_t localHeader = zipBase + localHeaderRel;
    if (localHeader + 30 > blob.size())
        return false;

    // Local file header signature: 50 4B 03 04
    if (!(blob[localHeader + 0] == 0x50 &&
          blob[localHeader + 1] == 0x4B &&
          blob[localHeader + 2] == 0x03 &&
          blob[localHeader + 3] == 0x04)) {
        return false;
    }

    // CRC in local header (4 bytes at +14)
    uint32_t crcLocal =
        (uint32_t)blob[localHeader + 14]        |
        ((uint32_t)blob[localHeader + 15] << 8) |
        ((uint32_t)blob[localHeader + 16] << 16)|
        ((uint32_t)blob[localHeader + 17] << 24);

    return (crcLocal == crcCentral);
}

REGISTER_PARSER(ZIPParser)
