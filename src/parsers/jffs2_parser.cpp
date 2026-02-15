#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>


class JFFS2Parser : public BaseParser {
public:
    std::string name() const override { return "JFFS2"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;

private:
    size_t detectFilesystem(const std::vector<uint8_t>& blob, size_t offset);
};

static constexpr uint16_t JFFS2_MAGIC = 0x1985;
static constexpr uint32_t DEFAULT_ERASEBLOCK = 0x20000; // 128 KB typical

#pragma pack(push, 1)
struct Jffs2RawNodeRef {
    uint16_t magic;
    uint16_t nodetype;
    uint32_t totlen;
    uint32_t hdr_crc;
};
#pragma pack(pop)

bool JFFS2Parser::match(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + sizeof(Jffs2RawNodeRef) > blob.size())
        return false;

    auto* hdr = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[offset]);
    return hdr->magic == JFFS2_MAGIC;
}

ScanResult JFFS2Parser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    size_t length = detectFilesystem(blob, offset);

    ScanResult result;
    result.offset = offset;
    result.type = "JFFS2";
    result.extractorType = "JFFS2";
    result.length = length;
    result.isValid = (length > 0);
    result.info = "Detected JFFS2 filesystem";
    return result;
}

size_t JFFS2Parser::detectFilesystem(const std::vector<uint8_t>& blob, size_t offset) {
    size_t pos = offset;
    size_t size = blob.size();

    // Require first node to be valid
    if (pos + sizeof(Jffs2RawNodeRef) > size)
        return 0;

    auto* hdr = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[pos]);
    if (hdr->magic != JFFS2_MAGIC)
        return 0;

    // Move to next eraseblock boundary
    size_t ebSize = DEFAULT_ERASEBLOCK;
    size_t startEB = offset - (offset % ebSize);
    size_t end = startEB + ebSize;

    if (end <= offset)
        end += ebSize;

    // Scan eraseblock by eraseblock
    size_t emptyBlocks = 0;
    const size_t MAX_EMPTY = 4; // stop after too many empty blocks

    while (end + sizeof(Jffs2RawNodeRef) < size) {
        bool foundNode = false;

        // Scan inside this eraseblock
        for (size_t p = end; p < end + ebSize && p + sizeof(Jffs2RawNodeRef) < size; p += 4) {
            auto* h = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[p]);

            if (h->magic == JFFS2_MAGIC) {
                foundNode = true;
                break;
            }
        }

        if (!foundNode) {
            emptyBlocks++;
            if (emptyBlocks >= MAX_EMPTY)
                break;
        } else {
            emptyBlocks = 0;
        }

        end += ebSize;
    }

    return end - offset;
}

REGISTER_PARSER(JFFS2Parser)
