#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"


class FATParser : public BaseParser {
public:
    std::string name() const override { return "FAT"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        // Need at least one sector (boot sector is 512 bytes, sometimes more, but 512 is safe minimum)
        if (offset + 64 > blob.size()) return false;

        // Check x86 jump at start: EB xx 90 or E9 xx xx
        uint8_t b0 = blob[offset];
        uint8_t b1 = blob[offset + 1];
        uint8_t b2 = blob[offset + 2];
        bool jump_ok =
            (b0 == 0xEB && b2 == 0x90) || // short jump + NOP
            (b0 == 0xE9);                // near jump

        if (!jump_ok)
            return false;

        // Check for "FAT" / "FAT32" labels in expected places (not strictly required, but reduces FPs)
        // FAT12/16: at offset 54 (0x36) the filesystem type string, 8 bytes
        // FAT32   : at offset 82 (0x52) the filesystem type string, 8 bytes
        bool hasFatString = false;
        if (offset + 62 <= blob.size()) {
            if (blob[offset + 54] == 'F' &&
                blob[offset + 55] == 'A' &&
                blob[offset + 56] == 'T')
                hasFatString = true;
        }
        if (offset + 90 <= blob.size()) {
            if (blob[offset + 82] == 'F' &&
                blob[offset + 83] == 'A' &&
                blob[offset + 84] == 'T')
                hasFatString = true;
        }

        return hasFatString;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "FAT";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 0;

        if (offset + 64 > blob.size()) {
            r.info = "Truncated FAT boot sector";
            r.length = blob.size() - offset;
            return r;
        }

        // BIOS Parameter Block common fields
        uint16_t bytesPerSector   = read_le16(blob, offset + 11);
        uint8_t  sectorsPerCluster= blob[offset + 13];
        uint16_t reservedSectors  = read_le16(blob, offset + 14);
        uint8_t  numFATs          = blob[offset + 16];
        uint16_t rootEntries      = read_le16(blob, offset + 17);
        uint16_t totalSectors16   = read_le16(blob, offset + 19);
        uint8_t  media            = blob[offset + 21];
        uint16_t sectorsPerFAT16  = read_le16(blob, offset + 22);
        uint32_t totalSectors32   = read_le32(blob, offset + 32);

        // Derived total sectors
        uint32_t totalSectors = (totalSectors16 != 0) ? totalSectors16 : totalSectors32;

        // FAT32 extension
        uint32_t sectorsPerFAT32 = 0;
        if (offset + 72 <= blob.size()) {
            sectorsPerFAT32 = read_le32(blob, offset + 36);
        }

        uint32_t sectorsPerFAT = (sectorsPerFAT16 != 0) ? sectorsPerFAT16 : sectorsPerFAT32;

        // Basic plausibility checks
        bool bpOk = (bytesPerSector == 512 || bytesPerSector == 1024 ||
                     bytesPerSector == 2048 || bytesPerSector == 4096);
        bool spcOk = (sectorsPerCluster > 0 && sectorsPerCluster <= 128 && (sectorsPerCluster & (sectorsPerCluster - 1)) == 0);
        bool fatsOk = (numFATs >= 1 && numFATs <= 4);
        bool mediaOk = (media == 0xF0 || (media >= 0xF8 && media <= 0xFF));
        bool totalsOk = (totalSectors > 0);

        // Compute image size from BPB
        uint64_t imageSize = (uint64_t)totalSectors * (uint64_t)bytesPerSector;
        size_t available = blob.size() - offset;
        size_t len = (imageSize > 0 && imageSize <= available) ?
                     (size_t)imageSize : available;

        // Determine FAT type (rough heuristic like mkfs.fat)
        uint32_t rootDirSectors = ((uint32_t)rootEntries * 32 + (bytesPerSector - 1)) / bytesPerSector;
        uint32_t dataSectors = totalSectors - (reservedSectors + (uint32_t)numFATs * sectorsPerFAT + rootDirSectors);
        uint32_t clusterCount = (sectorsPerCluster > 0) ? (dataSectors / sectorsPerCluster) : 0;
        std::string fatType = "unknown";
        if (clusterCount < 4085)
            fatType = "FAT12";
        else if (clusterCount < 65525)
            fatType = "FAT16";
        else
            fatType = "FAT32";

        r.length = len;
        r.isValid = bpOk && spcOk && fatsOk && mediaOk && totalsOk;

        std::ostringstream info;
        info << "FAT filesystem (" << fatType << ")"
             << ", bytes/sector=" << bytesPerSector
             << ", sectors/cluster=" << (uint32_t)sectorsPerCluster
             << ", reserved=" << reservedSectors
             << ", FATs=" << (uint32_t)numFATs
             << ", sectors/FAT=" << sectorsPerFAT
             << ", totalSectors=" << totalSectors
             << ", size=" << imageSize << " bytes"
             << ", valid=" << r.isValid;
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(FATParser)
