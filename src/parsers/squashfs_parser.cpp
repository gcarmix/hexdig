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
    result.extractorType = result.type;
    result.isValid = false;
    if (offset + 96 > blob.size()) {
        return result;
    }

    // Try little-endian first
    uint32_t block_size_le   = read_le32(blob, offset + 28);
    uint32_t inode_count_le  = read_le32(blob, offset + 36);
    uint32_t fs_size_le      = read_le32(blob, offset + 40);
    uint16_t version_major_le = blob[offset + 32];
    uint16_t version_minor_le = blob[offset + 33];

    bool looksLE = (version_major_le < 10 &&
                    block_size_le > 0 &&
                    block_size_le < (1 << 20));

    uint32_t block_size, inode_count, fs_size;
    uint16_t version_major, version_minor;
    std::string endian;

    if (looksLE) {
        block_size    = block_size_le;
        inode_count   = inode_count_le;
        fs_size       = fs_size_le;
        version_major = version_major_le;
        version_minor = version_minor_le;
        endian        = "LE";
    } else {
        block_size    = read_be32(blob, offset + 28);
        inode_count   = read_be32(blob, offset + 36);
        fs_size       = read_be32(blob, offset + 40);
        version_major = blob[offset + 32]; // still single byte
        version_minor = blob[offset + 33];
        endian        = "BE";
    }

    std::ostringstream info;
    info << "v" << version_major << "." << version_minor
         << " (" << endian << ")"
         << ", Inodes: " << inode_count
         << ", Block: " << block_size;

    
    result.length = fs_size;
    result.offset = offset;
    result.info   = info.str();
    result.isValid = true;
    return result;
}




REGISTER_PARSER(SquashFSParser)