#include "base_parser.hpp"
#include "parser_registration.hpp"
#include "helpers.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cstdint>
#include "logger.hpp"
static const uint8_t ext_magic[][8] = {
    {0x53,0xEF,0x01,0x00,0x01,0x00,0x00,0x00},
    {0x53,0xEF,0x01,0x00,0x02,0x00,0x00,0x00},
    {0x53,0xEF,0x01,0x00,0x03,0x00,0x00,0x00},
    {0x53,0xEF,0x02,0x00,0x01,0x00,0x00,0x00},
    {0x53,0xEF,0x02,0x00,0x02,0x00,0x00,0x00},
    {0x53,0xEF,0x02,0x00,0x03,0x00,0x00,0x00},
};
class ExtParser : public BaseParser {
public:
    std::string name() const override { return "EXT"; }



bool match(const std::vector<uint8_t>& blob, size_t offset) override {
    if (offset + 0x38 + 8 > blob.size()) return false;

    for (auto& sig : ext_magic) {
        if (memcmp(&blob[offset + 0x38], sig, 8) == 0)
            return true;
    }

    return false;
}
ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
    ScanResult r;
    r.type = "EXT4";
    r.extractorType = "7Z";
    r.isValid = false;

    // Compute filesystem start
    if (offset < 1024) {
        r.info = "Invalid ext offset (too small)";
        Logger::error(r.info);
        return r;
    }

    size_t fs_offset = offset - 1024;
    r.offset = fs_offset;

    size_t sb = fs_offset + 1024;
    if (sb + 0x100 > blob.size()) {
        r.info = "Truncated ext superblock";
        Logger::error(r.info);
        return r;
    }

    // Validate magic
    uint16_t magic = read_le16(blob, sb + 0x38);
    if (magic != 0xEF53) {
        r.info = "Invalid ext magic";
        Logger::debug(to_hex(magic));
        Logger::error(r.info);
        return r;
    }

    // Read fields
    uint32_t inodes = read_le32(blob, sb + 0x00);
    uint32_t blocks = read_le32(blob, sb + 0x04);
    uint32_t first_data_block = read_le32(blob, sb + 0x14);
    uint32_t log_block_size = read_le32(blob, sb + 0x18);
    uint32_t blocks_per_group = read_le32(blob, sb + 0x20);
    uint32_t inodes_per_group = read_le32(blob, sb + 0x28);

    if (inodes == 0 || blocks == 0) {
        r.info = "Invalid ext counts";
        Logger::error(r.info);
        return r;
    }

    uint64_t block_size = 1024ULL << log_block_size;
    if (block_size < 1024 || block_size > (1ULL << 20)) {
        r.info = "Unreasonable block size";
        Logger::error(r.info);
        return r;
    }

    // Structural sanity. The 8-byte match at +0x38 has only ~12 plausible
    // realisations, so by-chance hits in arbitrary binaries are common —
    // tighten with cross-field checks the chance bytes won't satisfy.
    //   * first_data_block is 0 (block_size>=2048) or 1 (block_size==1024)
    //   * blocks/inodes per group must be nonzero and addressable by one
    //     bitmap block (block_size*8 entries).
    //   * inodes can't outnumber blocks*(block_size/128) — each inode is
    //     at least 128 bytes on disk.
    uint64_t bits_per_block = block_size * 8;
    uint64_t max_inodes = (uint64_t)blocks * (block_size / 128);
    bool plausible =
        (first_data_block == 0 || first_data_block == 1) &&
        blocks_per_group != 0 && blocks_per_group <= bits_per_block &&
        inodes_per_group != 0 && inodes_per_group <= bits_per_block &&
        (uint64_t)inodes <= max_inodes;
    if (!plausible) {
        r.info = "Implausible ext superblock fields (likely false positive)";
        Logger::debug(r.info);
        return r;
    }

    // Estimate filesystem size
    uint64_t fs_size = (uint64_t)blocks * block_size;
    if (fs_size > blob.size() - fs_offset)
        fs_size = blob.size() - fs_offset;

    r.length = fs_size;
    r.isValid = true;

    // Volume name
    std::string volName;
    for (size_t i = 0; i < 16; i++) {
        uint8_t c = blob[sb + 0x78 + i];
        if (c == 0) break;
        if (c >= 0x20 && c <= 0x7E)
            volName.push_back((char)c);
    }

    std::ostringstream info;
    info << "EXT filesystem, blocks=" << blocks
         << ", inodes=" << inodes
         << ", block_size=" << block_size;

    if (!volName.empty())
        info << ", volume=\"" << volName << "\"";

    r.info = info.str();
    return r;
}



    
};

REGISTER_PARSER(ExtParser);
