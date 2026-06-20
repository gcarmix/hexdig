#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <iomanip>

#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include "helpers.hpp"

// Partition type lookup
static const std::unordered_map<uint8_t,std::string> typeNames = {
    {0x07,"NTFS/exFAT"}, {0x83,"Linux"}, {0x82,"Linux swap"},
    {0x0B,"FAT32"}, {0x0C,"FAT32 LBA"}, {0x0E,"FAT16 LBA"},
    {0x05,"Extended"}, {0x0F,"Extended LBA"}, {0xA5,"FreeBSD"},
    {0xA6,"OpenBSD"}, {0xAF,"MacOS X HFS"}, {0xEE,"GPT protective"}
};

class MBRParser : public BaseParser {
public:
    std::string name() const override { return "MBR"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if(offset != 0)return false;
        if (offset + 512 > blob.size()) return false;
        return blob[offset + 510] == 0x55 && blob[offset + 511] == 0xAA;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "MBR";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 512;

        if (offset + 512 > blob.size()) {
            r.info = "Truncated MBR sector";
            r.length = blob.size() - offset;
            return r;
        }

        // Parse partition entries
        size_t partBase = offset + 446;
        std::ostringstream info;
        info << "DOS Master Boot Record";

        bool foundPartition = false;
        bool protectiveMbr = false;
        for (int i = 0; i < 4; i++) {
            size_t off = partBase + i * 16;
            uint8_t type = blob[off + 4];
            uint32_t lbaFirst = read_le32(blob, off + 8);
            uint32_t sectors  = read_le32(blob, off + 12);

            if (type != 0 && sectors > 0) {
                foundPartition = true;
                auto it = typeNames.find(type);
                std::string typeName = (it != typeNames.end()) ? it->second : "Unknown";
                uint64_t imageSize = (uint64_t)sectors * 512ULL;

                if (type == 0xEE) protectiveMbr = true;

                info << ", partition: " << typeName
                     << ", image size: " << imageSize << " bytes";
                break; // report first valid partition only
            }
        }

        // A protective MBR just shields a GPT disk; let the GPT parser drive the
        // extraction (from LBA 0) so the disk isn't decompressed twice.
        if (protectiveMbr) r.extractorType = "";

        r.isValid = foundPartition;
        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(MBRParser)

