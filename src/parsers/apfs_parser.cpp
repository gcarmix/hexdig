#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include "helpers.hpp"

// Parser for an APFS (Apple File System) container.
//
// An APFS container starts with the container superblock (nx_superblock_t),
// which begins with a 32-byte object header (obj_phys_t) followed by the
// superblock fields. All multi-byte fields are little-endian.
//
//   0x00  obj_phys_t      (8-byte Fletcher checksum, oid, xid, type, subtype)
//   0x20  nx_magic        'NXSB' (0x4253584E)
//   0x24  nx_block_size   uint32  (logical block size, e.g. 4096)
//   0x28  nx_block_count  uint64  (number of blocks in the container)
//   0x48  nx_uuid         16-byte container UUID
//
// Extraction is delegated to 7-Zip, whose APFS handler unpacks the volumes.
class APFSParser : public BaseParser {
    static constexpr size_t MAGIC_OFF   = 0x20;
    static constexpr size_t BLKSZ_OFF   = 0x24;
    static constexpr size_t BLKCNT_OFF  = 0x28;
    static constexpr size_t UUID_OFF    = 0x48;
    static constexpr size_t HEADER_MIN  = 0x58; // through the UUID field

    static bool isSaneBlockSize(uint32_t bs) {
        // Power of two, in the range APFS permits (512B .. 64KB).
        return bs >= 512 && bs <= 65536 && (bs & (bs - 1)) == 0;
    }

public:
    std::string name() const override { return "APFS"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override {
        if (offset + BLKCNT_OFF > blob.size()) return false;
        // nx_magic 'NXSB' at offset+0x20
        if (!(blob[offset + MAGIC_OFF + 0] == 'N' &&
              blob[offset + MAGIC_OFF + 1] == 'X' &&
              blob[offset + MAGIC_OFF + 2] == 'S' &&
              blob[offset + MAGIC_OFF + 3] == 'B'))
            return false;
        // Reject stray "NXSB" strings: the block size must be sane.
        return isSaneBlockSize(read_le32(blob, offset + BLKSZ_OFF));
    }

    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "APFS";
        r.extractorType = "7Z";   // handed off to the existing 7-Zip extractor
        r.isValid = false;

        if (offset + HEADER_MIN > blob.size()) {
            r.length = blob.size() - offset;
            r.info = "Truncated APFS container superblock";
            return r;
        }

        uint32_t blockSize  = read_le32(blob, offset + BLKSZ_OFF);
        uint64_t blockCount = read_le64(blob, offset + BLKCNT_OFF);

        // container size = block_size * block_count, guarding against overflow.
        uint64_t containerSize = 0;
        bool sizeKnown = false;
        if (blockCount != 0 && blockSize != 0 &&
            blockCount <= (UINT64_MAX / blockSize)) {
            containerSize = (uint64_t)blockSize * blockCount;
            sizeKnown = true;
        }

        // Format the 16-byte container UUID as 8-4-4-4-12 hex.
        std::ostringstream uuid;
        uuid << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; i++) {
            uuid << std::setw(2) << (int)blob[offset + UUID_OFF + i];
            if (i == 3 || i == 5 || i == 7 || i == 9) uuid << '-';
        }

        std::ostringstream info;
        info << "APFS container, block size=" << blockSize
             << ", blocks=" << blockCount;
        if (sizeKnown) info << ", size=" << containerSize << " bytes";
        info << ", UUID=" << uuid.str();

        // Advance the scan cursor past the whole container when its size is
        // known and present; otherwise fall back to the remaining bytes.
        size_t remaining = blob.size() - offset;
        if (sizeKnown && containerSize <= remaining)
            r.length = (size_t)containerSize;
        else
            r.length = remaining;

        r.isValid = isSaneBlockSize(blockSize) && blockCount > 0;
        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(APFSParser)
