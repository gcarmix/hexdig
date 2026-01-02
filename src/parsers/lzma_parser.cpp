#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include "helpers.hpp"
//#define USE_LIBLZMA
#ifdef USE_LIBLZMA
#include <lzma.h>
#endif

// Common LZMA properties and dictionary sizes (like binwalk)
static const uint8_t supported_props[] = {0x5D, 0x6E, 0x6D, 0x6C};
static const uint32_t supported_dicts[] = {
    0x1000000, 0x2000000, 0x01000000, 0x02000000, 0x04000000,
    0x00800000, 0x00400000, 0x00200000, 0x00100000,
    0x00080000, 0x00020000, 0x00010000
};

struct LZMAHeader {
    uint8_t props;
    uint32_t dictSize;
    uint64_t uncompressedSize;
};

static LZMAHeader parseHeader(const std::vector<uint8_t>& blob, size_t offset) {
    LZMAHeader h{};
    h.props = blob[offset];
    h.dictSize = blob[offset+1] |
                 (blob[offset+2] << 8) |
                 (blob[offset+3] << 16) |
                 (blob[offset+4] << 24);
    h.uncompressedSize = 0;
    for (int i=0; i<8; i++)
        h.uncompressedSize |= (uint64_t)blob[offset+5+i] << (8*i);
    return h;
}

class LZMAParser : public BaseParser {
public:
    std::string name() const override { return "LZMA"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 13 > blob.size()) return false;
        uint8_t props = blob[offset];
        uint32_t dict = blob[offset+1] |
                        (blob[offset+2] << 8) |
                        (blob[offset+3] << 16) |
                        (blob[offset+4] << 24);
        // Check against known props/dicts
        bool propOK = false, dictOK = false;
        for (auto p : supported_props) if (props == p) propOK = true;
        for (auto d : supported_dicts) if (dict == d) dictOK = true;
        return propOK && dictOK;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult res;
        res.offset = offset;
        res.type = "LZMA";
        res.extractorType =res.type;
        

        if (offset + 13 > blob.size()) {
            res.info = "Invalid header";
            res.length = 0;
            return res;
        }

        LZMAHeader h = parseHeader(blob, offset);

        std::ostringstream info;
        info << "LZMA compressed data, props=0x"
             << std::hex << std::setw(2) << std::setfill('0') << (int)h.props
             << std::dec << ", dict=" << h.dictSize;
        if (h.uncompressedSize != 0xFFFF'FFFF'FFFF'FFFFull)
            info << ", uncompressed=" << h.uncompressedSize;
        else
            info << ", uncompressed=unknown";

        res.info = info.str();
        res.length = blob.size() - offset; // compressed length (best guess)
        if(h.uncompressedSize > MAX_ANALYZED_FILE_SIZE)
        {
            res.isValid = false;
        }
#ifdef USE_LIBLZMA
        // Dry-run validation
        std::vector<uint8_t> out;
        if (extract(blob, offset, out)) {
            res.length = blob.size() - offset;
            info << ", decompression OK, output=" << out.size() << " bytes";
            res.info = info.str();
            res.isValid = true;
        } else {
            res.isValid = false;
            res.info += ", decompression failed";
        }
#endif
        
        return res;
    }

#ifdef USE_LIBLZMA
    bool extract(const std::vector<uint8_t>& blob, size_t offset,
                 std::vector<uint8_t>& out) {
        if (offset + 13 > blob.size()) return false;

        const uint8_t* comp = &blob[offset];
        size_t comp_len = blob.size() - offset;

        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_alone_decoder(&strm, UINT64_MAX);
        if (ret != LZMA_OK) return false;

        strm.next_in = comp;
        strm.avail_in = comp_len;

        std::vector<uint8_t> buf(1 << 16);
        while (true) {
            strm.next_out = buf.data();
            strm.avail_out = buf.size();
            ret = lzma_code(&strm, LZMA_FINISH);
            if (ret != LZMA_OK && ret != LZMA_STREAM_END && ret != LZMA_BUF_ERROR) {
                lzma_end(&strm);
                return false;
            }
            size_t produced = buf.size() - strm.avail_out;
            out.insert(out.end(), buf.data(), buf.data() + produced);
            if (ret == LZMA_STREAM_END) break;
            if (ret == LZMA_BUF_ERROR && strm.avail_in == 0) break;
        }
        lzma_end(&strm);
        return true;
    }
#endif
};

REGISTER_PARSER(LZMAParser)
