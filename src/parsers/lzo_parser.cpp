#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include "helpers.hpp"
#include "lzop.hpp"

// Parser for the lzop (.lzo) container: LZO1X compressed data wrapped with the
// lzop file header and a chain of compressed blocks. The extractor of the same
// name performs the actual decompression.
class LZOParser : public BaseParser {
public:
    std::string name() const override { return "LZO"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override {
        return is_lzop_magic(blob, offset);
    }

    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "LZO";
        r.extractorType = "LZO";
        r.isValid = false;

        LzopHeader h;
        if (!parse_lzop_header(blob, offset, h)) {
            r.length = 0;
            r.info = "Truncated or invalid lzop header";
            return r;
        }

        // Walk the block chain to determine the exact stream length and validate
        // that every block fits inside the blob.
        size_t p = h.blockStart;
        uint64_t totalUncompressed = 0;
        size_t blocks = 0;
        bool truncated = false;

        for (;;) {
            uint32_t dstLen = 0;
            if (!lzop_rd32(blob, p, dstLen)) { truncated = true; break; }
            if (dstLen == 0) break; // end-of-stream marker

            uint32_t srcLen = 0;
            if (!lzop_rd32(blob, p, srcLen)) { truncated = true; break; }
            if (srcLen == 0 || srcLen > dstLen) { truncated = true; break; }

            // Per-block checksums (uncompressed, then compressed).
            if (h.flags & LZOP_F_ADLER32_D) p += 4;
            if (h.flags & LZOP_F_CRC32_D)   p += 4;
            if (srcLen < dstLen) {
                if (h.flags & LZOP_F_ADLER32_C) p += 4;
                if (h.flags & LZOP_F_CRC32_C)   p += 4;
            }

            p += srcLen; // compressed (or stored) payload
            if (p > blob.size()) { truncated = true; break; }

            totalUncompressed += dstLen;
            blocks++;
        }

        std::ostringstream info;
        info << "lzop compressed data, version=0x" << std::hex << std::setw(4)
             << std::setfill('0') << h.version << std::dec
             << ", method=" << (int)h.method;
        if (h.version >= LZOP_VERSION_0940)
            info << ", level=" << (int)h.level;
        if (!h.name.empty())
            info << ", original filename=\"" << h.name << "\"";

        if (truncated) {
            info << " (truncated)";
            r.length = blob.size() - offset;
            r.isValid = false;
        } else {
            info << ", blocks=" << blocks
                 << ", uncompressed=" << totalUncompressed;
            r.length = p - offset;
            r.isValid = (blocks > 0 && totalUncompressed > 0 &&
                         totalUncompressed <= MAX_ANALYZED_FILE_SIZE);
        }

        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(LZOParser)
