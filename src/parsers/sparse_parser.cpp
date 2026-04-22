#include "base_parser.hpp"
#include "parser_registration.hpp"
#include "helpers.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <iomanip>

// Android sparse image (simg) parser.
//
// Layout:
//   sparse_header (28 bytes, LE):
//     0  magic            0xed26ff3a
//     4  major_version    1
//     6  minor_version    0
//     8  file_hdr_sz      28
//    10  chunk_hdr_sz     12
//    12  blk_sz           (bytes, typically 4096, must be multiple of 4)
//    16  total_blks       (count in the unsparsified output)
//    20  total_chunks
//    24  image_checksum   (CRC32, often 0)
//
// Each chunk:
//   chunk_header (12 bytes, LE):
//     0  chunk_type   0xCAC1 RAW / 0xCAC2 FILL / 0xCAC3 DONT_CARE / 0xCAC4 CRC32
//     2  reserved
//     4  chunk_sz     (count of output blocks the chunk represents)
//     8  total_sz     (bytes of chunk in the file, including header)

static constexpr uint32_t SPARSE_MAGIC      = 0xed26ff3a;
static constexpr uint16_t SPARSE_CHUNK_RAW  = 0xCAC1;
static constexpr uint16_t SPARSE_CHUNK_FILL = 0xCAC2;
static constexpr uint16_t SPARSE_CHUNK_DC   = 0xCAC3;
static constexpr uint16_t SPARSE_CHUNK_CRC  = 0xCAC4;
static constexpr size_t   SPARSE_HDR_SIZE   = 28;
static constexpr size_t   SPARSE_CHUNK_HDR  = 12;

class SparseParser : public BaseParser {
public:
    std::string name() const override { return "SPARSE"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + SPARSE_HDR_SIZE > blob.size()) return false;
        return read_le32(blob, offset) == SPARSE_MAGIC;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "SPARSE";
        r.extractorType = "SPARSE";
        r.isValid = false;
        r.length = 0;

        if (offset + SPARSE_HDR_SIZE > blob.size()) {
            r.info = "Truncated sparse header";
            return r;
        }

        uint32_t magic        = read_le32(blob, offset + 0);
        uint16_t major_ver    = read_le16(blob, offset + 4);
        uint16_t minor_ver    = read_le16(blob, offset + 6);
        uint16_t file_hdr_sz  = read_le16(blob, offset + 8);
        uint16_t chunk_hdr_sz = read_le16(blob, offset + 10);
        uint32_t blk_sz       = read_le32(blob, offset + 12);
        uint32_t total_blks   = read_le32(blob, offset + 16);
        uint32_t total_chunks = read_le32(blob, offset + 20);
        uint32_t checksum     = read_le32(blob, offset + 24);

        if (magic != SPARSE_MAGIC) {
            r.info = "Invalid sparse magic";
            return r;
        }

        bool plausible = (major_ver == 1)
                      && (file_hdr_sz  >= SPARSE_HDR_SIZE)
                      && (chunk_hdr_sz >= SPARSE_CHUNK_HDR)
                      && (blk_sz >= 4) && (blk_sz % 4 == 0)
                      && (total_chunks > 0);
        if (!plausible) {
            r.info = "Sparse header fields out of range";
            return r;
        }

        // Walk chunks to compute total length and validate structure.
        size_t pos = offset + file_hdr_sz;
        uint64_t outBlocks = 0;
        uint32_t cRaw = 0, cFill = 0, cDc = 0, cCrc = 0;
        bool ok = true;

        for (uint32_t i = 0; i < total_chunks; i++) {
            if (pos + chunk_hdr_sz > blob.size()) { ok = false; break; }
            uint16_t ct       = read_le16(blob, pos + 0);
            uint32_t chunk_sz = read_le32(blob, pos + 4);
            uint32_t total_sz = read_le32(blob, pos + 8);

            if (total_sz < chunk_hdr_sz) { ok = false; break; }
            if (pos + total_sz > blob.size()) { ok = false; break; }

            uint64_t bytes_out = (uint64_t)chunk_sz * blk_sz;
            uint32_t payload_sz = total_sz - chunk_hdr_sz;

            switch (ct) {
                case SPARSE_CHUNK_RAW:
                    // RAW: payload must equal chunk_sz * blk_sz.
                    if (payload_sz != bytes_out) { ok = false; }
                    cRaw++;
                    break;
                case SPARSE_CHUNK_FILL:
                    // FILL: payload is exactly 4 bytes.
                    if (payload_sz != 4) { ok = false; }
                    cFill++;
                    break;
                case SPARSE_CHUNK_DC:
                    // DONT_CARE: no payload.
                    if (payload_sz != 0) { ok = false; }
                    cDc++;
                    break;
                case SPARSE_CHUNK_CRC:
                    if (payload_sz != 4) { ok = false; }
                    cCrc++;
                    break;
                default:
                    ok = false;
                    break;
            }
            if (!ok) break;

            outBlocks += chunk_sz;
            pos += total_sz;
        }

        r.length  = pos - offset;
        r.isValid = ok;

        std::ostringstream info;
        info << "Android sparse image v" << major_ver << "." << minor_ver
             << ", block size=" << blk_sz
             << ", total blocks=" << total_blks
             << " (" << ((uint64_t)total_blks * blk_sz) << " bytes unsparsified)"
             << ", chunks=" << total_chunks
             << " [RAW=" << cRaw
             << ", FILL=" << cFill
             << ", DC=" << cDc
             << ", CRC=" << cCrc << "]";
        if (checksum) {
            info << ", checksum=0x" << std::hex << std::setw(8)
                 << std::setfill('0') << checksum << std::dec;
        }
        if (!ok) info << " (truncated or malformed)";
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(SparseParser)
