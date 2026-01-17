#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <zlib.h>

class PNGParser : public BaseParser {
public:
    std::string name() const override { return "PNG"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;
};

bool PNGParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    // Binwalk-style signature:
    // PNG magic + IHDR length=13 + "IHDR"
    static const uint8_t sig[] = {
        0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, // IHDR length = 13
        'I', 'H', 'D', 'R'
    };

    if (offset + sizeof(sig) > blob.size())
        return false;

    return std::memcmp(&blob[offset], sig, sizeof(sig)) == 0;
}

ScanResult PNGParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    ScanResult r;
    r.type = "PNG";
    r.offset = offset;
    r.extractorType = "RAW";
    r.isValid = false;
    r.length = 0;

    size_t pos = offset + 8; // skip PNG signature

    // --- Parse IHDR ---
    if (pos + 8 + 13 + 4 > blob.size()) {
        r.info = "Invalid PNG: truncated IHDR";
        return r;
    }

    uint32_t ihdr_len =
        (blob[pos] << 24) | (blob[pos+1] << 16) |
        (blob[pos+2] << 8) | blob[pos+3];

    if (ihdr_len != 13) {
        r.info = "Invalid PNG: IHDR length != 13";
        return r;
    }

    pos += 4; // skip length

    const uint8_t* ihdr_type = &blob[pos];
    if (std::memcmp(ihdr_type, "IHDR", 4) != 0) {
        r.info = "Invalid PNG: missing IHDR";
        return r;
    }

    pos += 4; // skip type

    // Extract width/height
    if (pos + 13 > blob.size()) {
        r.info = "Invalid PNG: truncated IHDR data";
        return r;
    }

    size_t width =
        (blob[pos] << 24) | (blob[pos+1] << 16) |
        (blob[pos+2] << 8) | blob[pos+3];

    size_t height =
        (blob[pos+4] << 24) | (blob[pos+5] << 16) |
        (blob[pos+6] << 8) | blob[pos+7];

    pos += ihdr_len; // skip IHDR data

    // IHDR CRC
    if (pos + 4 > blob.size()) {
        r.info = "Invalid PNG: missing IHDR CRC";
        return r;
    }

    uint32_t stored_crc =
        (blob[pos] << 24) | (blob[pos+1] << 16) |
        (blob[pos+2] << 8) | blob[pos+3];

    uint32_t computed_crc = crc32(0L, Z_NULL, 0);
    computed_crc = crc32(computed_crc, ihdr_type, 4 + ihdr_len);

    if (stored_crc != computed_crc) {
        r.info = "Invalid PNG: IHDR CRC mismatch";
        return r;
    }

    pos += 4; // skip IHDR CRC

    // --- Walk chunks ---
    while (pos + 12 <= blob.size()) {
        uint32_t len =
            (blob[pos] << 24) | (blob[pos+1] << 16) |
            (blob[pos+2] << 8) | blob[pos+3];

        pos += 4;

        const uint8_t* type = &blob[pos];
        pos += 4;

        if (pos + len + 4 > blob.size()) {
            r.info = "Invalid PNG: chunk exceeds file bounds";
            return r;
        }

        // CRC for this chunk
        uint32_t stored =
            (blob[pos + len] << 24) |
            (blob[pos + len + 1] << 16) |
            (blob[pos + len + 2] << 8) |
            blob[pos + len + 3];

        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, type, 4 + len);

        if (crc != stored) {
            r.info = "Invalid PNG: chunk CRC mismatch";
            return r;
        }

        if (std::memcmp(type, "IEND", 4) == 0) {
            pos += len + 4;
            r.isValid = true;
            r.length = pos - offset;

            std::ostringstream info;
            info << "Resolution: " << width << "x" << height;
            r.info = info.str();
            return r;
        }

        pos += len + 4; // skip data + CRC
    }

    r.info = "Invalid PNG: missing IEND";
    return r;
}

REGISTER_PARSER(PNGParser)
