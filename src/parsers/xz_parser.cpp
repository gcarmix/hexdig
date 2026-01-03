#include "parser_registration.hpp"
#include <algorithm>
#include <string>
#include "scanner.hpp"
#include <optional>
#include <zlib.h>
#include "helpers.hpp"
#include "logger.hpp"

static const uint8_t XZ_MAGIC[6] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
static const uint8_t XZ_FOOTER_MAGIC[2] = {0x59, 0x5A}; // "YZ"



class XZParser : public BaseParser {
public:
    std::string name() const override { return "XZ"; };
    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override;

private:
    bool parse_xz_header(const std::vector<uint8_t>& data, std::size_t offset);
    std::optional<size_t> find_xz_stream_size(const std::vector<uint8_t>& data, size_t offset);
};

bool XZParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    if (offset + 6 > blob.size()) return false;
    return std::equal(std::begin(XZ_MAGIC), std::end(XZ_MAGIC), blob.begin() + offset);
}

// Validate the 12-byte XZ Stream Header
bool XZParser::parse_xz_header(const std::vector<uint8_t>& data, std::size_t offset) {
    if (offset + 12 > data.size()) return false;

    if (!std::equal(std::begin(XZ_MAGIC), std::end(XZ_MAGIC), data.begin() + offset))
        return false;

    // CRC32 of bytes [6..7] (Stream Flags)
    uint32_t crc_stored = read_le32(data, offset + 8);

    uint32_t crc_calc = crc32(0L, Z_NULL, 0);
    crc_calc = crc32(crc_calc, data.data() + offset + 6, 2);

    return crc_stored == crc_calc;
}

// Parse XZ footer and compute full stream size
std::optional<size_t> XZParser::find_xz_stream_size(const std::vector<uint8_t>& data, size_t offset) {
    // Minimum XZ stream is 12-byte header + 12-byte footer
    if (offset + 24 > data.size()) return std::nullopt;

    // Footer is always last 12 bytes of the stream
    // But we don't know where the stream ends, so we scan forward
    size_t pos = offset + 12; // skip header

    while (pos + 12 <= data.size()) {
        // Check footer magic at pos+10..11
        if (data[pos + 10] == XZ_FOOTER_MAGIC[0] &&
            data[pos + 11] == XZ_FOOTER_MAGIC[1]) {

            // Validate footer CRC
            uint32_t crc_stored = read_le32(data, pos);
            uint32_t crc_calc = crc32(0L, Z_NULL, 0);
            crc_calc = crc32(crc_calc, data.data() + pos + 4, 6);

            if (crc_stored != crc_calc) {
                pos++;
                continue;
            }

            // Backward Size (in 4-byte units minus 1)
            uint32_t backward_size = read_le32(data, pos + 4);
            size_t index_size = (size_t)(backward_size + 1) * 4;

            // Full stream size = header + blocks + index + footer
            size_t stream_size = (pos - offset) + 12;

            return stream_size;
        }

        pos++;
    }

    return std::nullopt;
}

ScanResult XZParser::parse(const std::vector<std::uint8_t>& blob, size_t offset) {
    ScanResult result;
    result.offset = offset;
    result.length = 0;
    result.type = name();
    result.extractorType = "7Z";
    result.info = "XZ compressed stream";
    result.isValid = false;

    size_t nextOffset = offset;
    size_t streamCount = 0;

    while (nextOffset < blob.size()) {
        if (!parse_xz_header(blob, nextOffset))
            break;

        auto sizeOpt = find_xz_stream_size(blob, nextOffset);
        if (!sizeOpt.has_value())
            break;

        size_t streamSize = *sizeOpt;
        result.length += streamSize;
        nextOffset += streamSize;
        streamCount++;
    }

    result.isValid = (streamCount > 0);

    if (result.isValid) {
        result.info += ", streams=" + std::to_string(streamCount) +
                       ", total size=" + std::to_string(result.length) + " bytes";
    }

    return result;
}

REGISTER_PARSER(XZParser)
