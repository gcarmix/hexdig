#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <tuple>
#include "helpers.hpp"

class SquashFSParser : public BaseParser {
public:
    std::string name() const override { return "SquashFS"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;
};

bool SquashFSParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + 4 > blob.size()) return false;

    // Little-endian magic: "sqsh" (0x73717368)
    bool leMagic = (blob[offset]     == 0x73 && // 's'
                    blob[offset + 1] == 0x71 && // 'q'
                    blob[offset + 2] == 0x73 && // 's'
                    blob[offset + 3] == 0x68);  // 'h'

    // Big-endian magic: "hsqs" (0x68737173)
    bool beMagic = (blob[offset]     == 0x68 && // 'h'
                    blob[offset + 1] == 0x73 && // 's'
                    blob[offset + 2] == 0x71 && // 'q'
                    blob[offset + 3] == 0x73);  // 's'

    return leMagic || beMagic;
}

ScanResult SquashFSParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    ScanResult result;
    result.type   = "SquashFS";
    result.extractorType = "7Z";
    result.offset = offset;
    result.isValid = false;
    if (offset + 96 > blob.size()) {
        return result;
    }

    // Endianness is encoded by the magic bytes themselves: "hsqs" -> LE,
    // "sqsh" -> BE. The match() function accepts both; pick the right reader.
    bool isLE = (blob[offset] == 0x68); // 'h' for "hsqs"
    auto rd16 = [&](size_t off) -> uint16_t { return isLE ? read_le16(blob, off) : read_be16(blob, off); };
    auto rd32 = [&](size_t off) -> uint32_t { return isLE ? read_le32(blob, off) : read_be32(blob, off); };
    auto rd64 = [&](size_t off) -> uint64_t {
        if (isLE) return (uint64_t)read_le32(blob, off) | ((uint64_t)read_le32(blob, off + 4) << 32);
        return ((uint64_t)read_be32(blob, off) << 32) | (uint64_t)read_be32(blob, off + 4);
    };

    // Squashfs v4 superblock layout (the only version still in active use):
    //   0x00 magic u32,  0x04 inodes u32,         0x08 mkfs_time u32,
    //   0x0C block_size u32, 0x10 fragments u32,  0x14 compression u16,
    //   0x16 block_log u16,  0x18 flags u16,      0x1A no_ids u16,
    //   0x1C s_major u16,    0x1E s_minor u16,    0x20 root_inode u64,
    //   0x28 bytes_used u64, ...
    uint16_t version_major = rd16(offset + 0x1C);
    uint16_t version_minor = rd16(offset + 0x1E);
    uint32_t block_size    = rd32(offset + 0x0C);
    uint32_t block_log     = rd16(offset + 0x16);
    uint32_t inodes        = rd32(offset + 0x04);
    uint64_t bytes_used    = rd64(offset + 0x28);

    std::ostringstream info;
    info << "v" << version_major << "." << version_minor
         << " (" << (isLE ? "LE" : "BE") << ")"
         << ", Inodes: " << inodes
         << ", Block: " << block_size;

    // Sanity-check the on-disk size. bytes_used is file-controlled and a 4-byte
    // magic is short, so reject implausible values rather than advancing the
    // scanner by a garbage length.
    size_t remaining = blob.size() - offset;
    bool plausible =
        version_major >= 1 && version_major <= 4 &&
        block_size >= 4096 && block_size <= (1u << 20) &&
        // block_log and block_size must agree: block_size == 1 << block_log
        block_log >= 12 && block_log <= 20 &&
        ((uint32_t)1 << block_log) == block_size &&
        bytes_used >= 96 && bytes_used <= remaining;
    if (!plausible) {
        result.length = std::min<size_t>(bytes_used, remaining);
        result.info   = info.str() + " (implausible superblock, likely false positive)";
        return result;
    }

    result.length  = (size_t)bytes_used;
    result.info    = info.str();
    result.isValid = true;
    return result;
}




REGISTER_PARSER(SquashFSParser)