#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"




class ARJParser : public BaseParser {
public:
    std::string name() const override { return "ARJ"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 4 > blob.size()) return false;

        // Magic check
        if (read_le16(blob, offset) != 0xEA60)
            return false;

        uint16_t mainHeaderSize = read_le16(blob, offset + 2);

        // Reject absurd header sizes
        if (mainHeaderSize < 20 || mainHeaderSize > 260)
            return false;

        // Check header CRC
        if (offset + 6 + mainHeaderSize > blob.size())
            return false;

        uint16_t storedCRC = read_le16(blob, offset + 4);
        uint16_t calcCRC   = crc16(&blob[offset + 6], (size_t)(mainHeaderSize - 2));

        if (storedCRC != calcCRC)
            return false;

        return true;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "ARJ";
        r.extractorType = "7Z";
        r.isValid = false;

        uint16_t mainHeaderSize = read_le16(blob, offset + 2);
        uint8_t version = blob[offset + 6];
        uint8_t flags   = blob[offset + 7];

        // Validate version and flags
        if (version == 0 || version > 4)
            return r;
        if (flags & 0xE0) // upper bits unused
            return r;

        size_t cursor = offset + 6 + mainHeaderSize;
        size_t fileCount = 0;
        bool trailerFound = false;

        while (cursor + 4 <= blob.size()) {
            if (read_le16(blob, cursor) != 0xEA60)
                break;

            uint16_t hdrSize = read_le16(blob, cursor + 2);

            // Trailer header
            if (hdrSize == 0) {
                trailerFound = true;
                break;
            }

            // Validate header CRC
            if (cursor + 6 + hdrSize > blob.size())
                break;

            uint16_t storedCRC = read_le16(blob, cursor + 4);
            uint16_t calcCRC   = crc16(&blob[cursor + 6], (size_t)(hdrSize - 2));

            if (storedCRC != calcCRC)
                break;

            cursor += 6 + hdrSize;
            fileCount++;
        }

        r.length = cursor - offset;
        r.isValid = trailerFound && fileCount > 0;

        std::ostringstream info;
        info << "ARJ archive, version=" << (int)version
             << ", flags=0x" << std::hex << (int)flags << std::dec
             << ", files=" << fileCount
             << (trailerFound ? ", trailer=OK" : ", trailer=MISSING");

        r.info = info.str();
        return r;
    }
};


REGISTER_PARSER(ARJParser)
