
#include "parser_registration.hpp"
#include <algorithm>
#include <string>
#include "scanner.hpp"
#include <optional>
#include <zlib.h>
#include <lzma.h>
#include "helpers.hpp"
#include "logger.hpp"

static const uint8_t XZ_MAGIC[6] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
class XZParser : public BaseParser {
public:
    std::string name() const override { return "XZ"; };
    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override;
private:
    std::optional<std::size_t> lzma_dry_run(const std::vector<uint8_t>& data, std::size_t offset);
    bool parse_xz_header(const std::vector<uint8_t>& data, std::size_t offset);

};

std::optional<std::size_t> XZParser::lzma_dry_run(const std::vector<uint8_t>& data, std::size_t offset) {
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&strm, UINT64_MAX, 0) != LZMA_OK)
        return std::nullopt;

    strm.next_in = data.data() + offset;
    strm.avail_in = data.size() - offset;

    std::vector<uint8_t> outBuf(32768);
    lzma_ret ret;
    size_t totalIn = 0;

    do {
        strm.next_out = outBuf.data();
        strm.avail_out = outBuf.size();

        ret = lzma_code(&strm, LZMA_RUN);
        totalIn = (strm.next_in - (data.data() + offset));

        if (ret == LZMA_STREAM_END) {
            lzma_end(&strm);
            return totalIn; // number of bytes consumed by this stream
        }
        if (ret != LZMA_OK) break;
    } while (strm.avail_in > 0);

    lzma_end(&strm);
    return std::nullopt; // failed or malformed stream
}

std::string hex(uint32_t v){
    char buf[9];               // 8 hex digits + '\0'
    std::snprintf(buf, sizeof(buf), "%08x", v);
    return std::string(buf);
}
bool XZParser::parse_xz_header(const std::vector<uint8_t>& data, std::size_t offset) {
    if (offset + 12 > data.size()) return false;

    static constexpr uint8_t XZ_MAGIC[] = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
    if (!std::equal(std::begin(XZ_MAGIC), std::end(XZ_MAGIC), data.begin() + offset))
        return false;

    // Verify CRC32 of header bytes [0..7]
    uint32_t crc_stored = read_le32(data,offset+8);
    uint32_t crc_calc = crc32(0L, Z_NULL, 0);
    crc_calc = crc32(crc_calc, data.data() + offset + 6, 2);
    return crc_stored == crc_calc;
}



bool XZParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    const uint8_t XZ_MAGIC[] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};

    if (offset + 6 > blob.size()) return false;

    for (size_t i = 0; i < 6; ++i) {
        if (blob[offset + i] != XZ_MAGIC[i]) return false;
    }

    return true;
}

ScanResult XZParser::parse(const std::vector<std::uint8_t>& blob,
                           size_t offset) {
                    
    ScanResult result;
    result.offset = offset;
    result.length = 0;
    result.type = name();
    result.extractorType = name();
    result.info = "XZ compressed stream";
    result.isValid = false;

    std::size_t nextOffset = offset;
    std::optional<std::size_t> previousOffset;
    std::size_t streamCount = 0;

    while (nextOffset < blob.size()) {
        if (!parse_xz_header(blob, nextOffset))
            break;
        auto sizeOpt = lzma_dry_run(blob, nextOffset);
        if (sizeOpt.has_value()) {
            streamCount++;
            result.length += *sizeOpt;
            nextOffset += *sizeOpt;
            previousOffset = nextOffset;
        } else {
            result.info += ", valid header with malformed data stream";
            break;
        }
    }

    result.isValid = (streamCount > 0);
    if (result.isValid && result.length > 0) {
        result.info += ", total size: " + std::to_string(result.length) + " bytes";
    }



    return result;
}


REGISTER_PARSER(XZParser)