#include "base_parser.hpp"
#include "parser_registration.hpp"
#include "helpers.hpp"
#include "gpt.hpp"

#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>

// EFI GPT (GUID Partition Table) parser.
//
// The "EFI PART" signature lives in the GPT header at LBA 1 (byte offset 512 on
// a 512-byte-sector disk), right after the protective MBR at LBA 0. We report
// the disk GUID and a summary of the partition entries, then hand the whole disk
// image (starting at LBA 0) to the 7-Zip extractor, whose GPT handler carves out
// each partition. Extraction must start at LBA 0 because partition entries use
// LBAs that are absolute from the start of the disk.

class GPTParser : public BaseParser {
public:
    std::string name() const override { return "GPT"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        return gpt::signature_at(blob, offset);
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "GPT";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = gpt::HEADER_MIN_SIZE;

        if (offset + gpt::HEADER_MIN_SIZE > blob.size()) {
            r.info = "Truncated GPT header";
            r.length = blob.size() - offset;
            return r;
        }

        gpt::Header h = gpt::read_header(blob, offset);

        // Reject implausible headers — every field below is file-controlled.
        if (h.revision == 0 ||
            h.headerSize < gpt::HEADER_MIN_SIZE ||
            h.partitionEntrySize < 128 ||
            (h.partitionEntrySize % 128) != 0 ||
            h.numPartitionEntries == 0) {
            r.info = "Invalid GPT header";
            return r;
        }

        const uint32_t ss = gpt::sector_size(offset, h.currentLba);

        // Byte offset of LBA 0 (the disk start) within the blob. Partition LBAs
        // are absolute from here, and 7-Zip needs the stream to begin here.
        uint64_t headerBytes = h.currentLba * static_cast<uint64_t>(ss);
        size_t base = (headerBytes <= offset) ? (offset - headerBytes) : 0;

        // Summarise the partition entry array (capped so a bogus count can't
        // make us walk off into unrelated data).
        size_t arr = base + h.partitionEntryLba * static_cast<uint64_t>(ss);
        uint32_t maxEntries = std::min<uint32_t>(h.numPartitionEntries, 256);

        std::ostringstream info;
        info << "EFI GPT, " << ss << "-byte sectors, disk GUID: " << h.diskGuid;

        uint32_t used = 0, shown = 0;
        for (uint32_t i = 0; i < maxEntries; ++i) {
            size_t e = arr + static_cast<size_t>(i) * h.partitionEntrySize;
            if (e + 128 > blob.size()) break;
            if (gpt::guid_is_zero(blob, e)) continue;  // unused slot

            ++used;
            if (shown < 8) {
                std::string typeGuid = gpt::format_guid(blob, e);
                uint64_t first = read_le64(blob, e + 32);
                uint64_t last  = read_le64(blob, e + 40);
                std::string nm = gpt::partition_name(blob, e + 56);
                uint64_t bytes = (last >= first)
                                     ? (last - first + 1) * static_cast<uint64_t>(ss)
                                     : 0;

                info << "; [" << i << "] " << gpt::type_name(typeGuid);
                if (!nm.empty()) info << " \"" << nm << "\"";
                info << " " << bytes << " bytes";
                ++shown;
            }
        }
        info << "; " << used << " partition(s)";

        // Span the whole disk: the backup GPT header sits at the last LBA.
        uint64_t diskEnd = base + (h.backupLba + 1) * static_cast<uint64_t>(ss);
        if (diskEnd <= base || diskEnd > blob.size()) diskEnd = blob.size();

        // Report (and extract) from LBA 0 so 7-Zip sees the full disk image.
        r.offset = base;
        r.length = diskEnd - base;
        r.info = info.str();
        r.isValid = true;
        return r;
    }
};

REGISTER_PARSER(GPTParser)
