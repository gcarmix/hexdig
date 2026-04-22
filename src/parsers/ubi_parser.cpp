#include "base_parser.hpp"
#include "parser_registration.hpp"
#include "helpers.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>

// UBI (Unsorted Block Images) — flash translation layer used on MTD devices.
// Each Physical Erase Block (PEB) starts with an Erase Counter (EC) header
// identified by magic "UBI#". The PEB size is not encoded in the header, so
// we infer it by searching for the next EC header at common PEB sizes.

static constexpr uint32_t UBI_EC_HDR_MAGIC  = 0x55424923; // "UBI#"
static constexpr uint32_t UBI_VID_HDR_MAGIC = 0x55424921; // "UBI!"
static constexpr size_t   UBI_EC_HDR_SIZE   = 64;

class UBIParser : public BaseParser {
public:
    std::string name() const override { return "UBI"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + UBI_EC_HDR_SIZE > blob.size()) return false;
        return read_be32(blob, offset) == UBI_EC_HDR_MAGIC;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "UBI";
        r.extractorType = "UBI";
        r.isValid = false;
        r.length = 0;

        if (offset + UBI_EC_HDR_SIZE > blob.size()) {
            r.info = "Truncated UBI EC header";
            r.length = blob.size() - offset;
            return r;
        }

        // ubi_ec_hdr layout (big-endian):
        //   0  magic (4)   "UBI#"
        //   4  version (1)
        //   5  padding1 (3)
        //   8  ec (8)              erase counter
        //  16  vid_hdr_offset (4)
        //  20  data_offset (4)
        //  24  image_seq (4)
        //  28  padding2 (32)
        //  60  hdr_crc (4)
        uint32_t magic          = read_be32(blob, offset + 0);
        uint8_t  version        = blob[offset + 4];
        uint64_t ec             = read_be64(blob, offset + 8);
        uint32_t vid_hdr_offset = read_be32(blob, offset + 16);
        uint32_t data_offset    = read_be32(blob, offset + 20);
        uint32_t image_seq      = read_be32(blob, offset + 24);

        if (magic != UBI_EC_HDR_MAGIC) {
            r.info = "Invalid UBI EC magic";
            return r;
        }

        // Detect PEB size by probing common sizes for another EC header.
        static const size_t candidates[] = {
            0x4000,   // 16K
            0x8000,   // 32K
            0x10000,  // 64K
            0x20000,  // 128K
            0x40000,  // 256K
            0x80000,  // 512K
            0x100000, // 1M
            0x200000  // 2M
        };
        size_t pebSize = 0;
        for (size_t cand : candidates) {
            size_t nextPeb = offset + cand;
            if (nextPeb + 4 > blob.size()) continue;
            if (read_be32(blob, nextPeb) == UBI_EC_HDR_MAGIC) {
                pebSize = cand;
                break;
            }
        }

        // Plausibility checks. UBI v1 is the only widely deployed version;
        // vid_hdr_offset sits after the EC header and data_offset follows it.
        bool plausible = (version == 1)
                      && (vid_hdr_offset >= UBI_EC_HDR_SIZE)
                      && (data_offset   >  vid_hdr_offset)
                      && (data_offset   <  0x400000);

        size_t pebCount = 0;
        size_t length   = 0;

        if (pebSize > 0) {
            // Walk forward, counting PEBs that either have an EC header or
            // are fully erased (all 0xFF in the first 64 bytes).
            size_t pos = offset;
            while (pos + pebSize <= blob.size()) {
                uint32_t m = read_be32(blob, pos);
                if (m == UBI_EC_HDR_MAGIC) {
                    pebCount++;
                    pos += pebSize;
                    continue;
                }
                bool erased = true;
                for (size_t i = 0; i < UBI_EC_HDR_SIZE; i++) {
                    if (blob[pos + i] != 0xFF) { erased = false; break; }
                }
                if (erased) {
                    pebCount++;
                    pos += pebSize;
                    continue;
                }
                break;
            }
            length = pebCount * pebSize;
        } else {
            length = UBI_EC_HDR_SIZE;
        }

        r.length  = length;
        r.isValid = plausible && pebSize > 0 && pebCount > 0;

        std::ostringstream info;
        info << "UBI image, version=" << (int)version
             << ", EC=" << ec
             << ", VID hdr offset=" << vid_hdr_offset
             << ", data offset=" << data_offset
             << ", image_seq=0x" << std::hex << image_seq << std::dec;
        if (pebSize > 0) {
            info << ", PEB size=" << pebSize
                 << ", PEBs=" << pebCount;
        } else {
            info << ", PEB size=unknown";
        }
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(UBIParser)
