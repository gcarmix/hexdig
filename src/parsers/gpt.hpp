#pragma once
// Shared definitions for the EFI GPT (GUID Partition Table) parser/extractor.
//
// On-disk layout (UEFI spec):
//   LBA 0          : protective MBR (handled by the MBR parser)
//   LBA 1          : primary GPT header  ("EFI PART")
//   LBA 2..        : primary partition entry array
//   ... usable area ...
//   last LBA       : secondary (backup) GPT header
//
// All multi-byte header/entry integers are little-endian. GUIDs use the
// Microsoft "mixed-endian" layout (first three groups little-endian, last
// two big-endian).

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <cstdio>
#include <unordered_map>
#include "helpers.hpp"

namespace gpt {

// 8-byte signature at the start of the GPT header: "EFI PART".
static constexpr std::array<uint8_t, 8> SIGNATURE = {
    0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54
};

static constexpr size_t HEADER_MIN_SIZE = 92;

// GPT header field offsets (relative to the header start).
struct Header {
    uint32_t revision;
    uint32_t headerSize;
    uint32_t headerCrc32;
    uint64_t currentLba;
    uint64_t backupLba;
    uint64_t firstUsableLba;
    uint64_t lastUsableLba;
    std::string diskGuid;
    uint64_t partitionEntryLba;
    uint32_t numPartitionEntries;
    uint32_t partitionEntrySize;
    uint32_t partitionArrayCrc32;
};

// Format a 16-byte GUID (mixed-endian) as the canonical uppercase string
// XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
inline std::string format_guid(const std::vector<uint8_t>& blob, size_t off) {
    if (off + 16 > blob.size()) return std::string("<truncated>");
    const uint8_t* g = &blob[off];
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g[3], g[2], g[1], g[0],   // Data1 (LE)
        g[5], g[4],               // Data2 (LE)
        g[7], g[6],               // Data3 (LE)
        g[8], g[9],               // Data4 (BE)
        g[10], g[11], g[12], g[13], g[14], g[15]);
    return std::string(buf);
}

inline bool guid_is_zero(const std::vector<uint8_t>& blob, size_t off) {
    if (off + 16 > blob.size()) return true;
    for (size_t i = 0; i < 16; ++i)
        if (blob[off + i] != 0) return false;
    return true;
}

// Well-known partition type GUIDs.
inline std::string type_name(const std::string& guid) {
    static const std::unordered_map<std::string, std::string> names = {
        {"C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI System"},
        {"21686148-6449-6E6F-744E-656564454649", "BIOS boot"},
        {"024DEE41-33E7-11D3-9D69-0008C781F39F", "MBR partition scheme"},
        {"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Microsoft basic data"},
        {"E3C9E316-0B5C-4DB8-817D-F92DF00215AE", "Microsoft reserved"},
        {"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", "Windows recovery"},
        {"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", "Windows LDM metadata"},
        {"AF9B60A0-1431-4F62-BC68-3311714A69AD", "Windows LDM data"},
        {"0FC63DAF-8483-4772-8E79-3D69D8477DE4", "Linux filesystem"},
        {"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", "Linux swap"},
        {"E6D6D379-F507-44C2-A23C-238F2A3DF928", "Linux LVM"},
        {"A19D880F-05FC-4D3B-A006-743F0F84911E", "Linux RAID"},
        {"44479540-F297-41B2-9AF7-D131D5F0458A", "Linux root (x86)"},
        {"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "Linux root (x86-64)"},
        {"BC13C2FF-59E6-4262-A352-B275FD6F7172", "Linux /boot (ext)"},
        {"933AC7E1-2EB4-4F13-B844-0E14E2AEF915", "Linux /home"},
        {"3B8F8425-20E0-4F3B-907F-1A25A76F98E8", "Linux /srv"},
        {"48465300-0000-11AA-AA11-00306543ECAC", "Apple HFS+"},
        {"7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple APFS"},
        {"55465300-0000-11AA-AA11-00306543ECAC", "Apple UFS"},
        {"516E7CB4-6ECF-11D6-8FF8-00022D09712B", "FreeBSD data"},
        {"83BD6B9D-7F41-11DC-BE0B-001560B84F0F", "FreeBSD boot"},
        {"516E7CB6-6ECF-11D6-8FF8-00022D09712B", "FreeBSD UFS"},
        {"516E7CBA-6ECF-11D6-8FF8-00022D09712B", "FreeBSD ZFS"},
    };
    auto it = names.find(guid);
    return it != names.end() ? it->second : std::string("Unknown");
}

// Decode the 72-byte UTF-16LE partition name into a printable ASCII string.
inline std::string partition_name(const std::vector<uint8_t>& blob, size_t off) {
    std::string out;
    for (size_t i = 0; i + 1 < 72; i += 2) {
        if (off + i + 1 >= blob.size()) break;
        uint16_t c = read_le16(blob, off + i);
        if (c == 0) break;
        out += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    return out;
}

// Parse the fixed header fields starting at `off`. Caller must ensure at least
// HEADER_MIN_SIZE bytes are available.
inline Header read_header(const std::vector<uint8_t>& blob, size_t off) {
    Header h{};
    h.revision            = read_le32(blob, off + 8);
    h.headerSize          = read_le32(blob, off + 12);
    h.headerCrc32         = read_le32(blob, off + 16);
    h.currentLba          = read_le64(blob, off + 24);
    h.backupLba           = read_le64(blob, off + 32);
    h.firstUsableLba      = read_le64(blob, off + 40);
    h.lastUsableLba       = read_le64(blob, off + 48);
    h.diskGuid            = format_guid(blob, off + 56);
    h.partitionEntryLba   = read_le64(blob, off + 72);
    h.numPartitionEntries = read_le32(blob, off + 80);
    h.partitionEntrySize  = read_le32(blob, off + 84);
    h.partitionArrayCrc32 = read_le32(blob, off + 88);
    return h;
}

inline bool signature_at(const std::vector<uint8_t>& blob, size_t off) {
    if (off + SIGNATURE.size() > blob.size()) return false;
    for (size_t i = 0; i < SIGNATURE.size(); ++i)
        if (blob[off + i] != SIGNATURE[i]) return false;
    return true;
}

// The GPT header lives at LBA 1, so the byte offset of the header equals one
// sector size. Derive it from the header's currentLba field when possible and
// only accept the two standard sector sizes; otherwise fall back to 512.
inline uint32_t sector_size(size_t headerOffset, uint64_t currentLba) {
    if (currentLba != 0 && headerOffset % currentLba == 0) {
        uint64_t cand = headerOffset / currentLba;
        if (cand == 512 || cand == 4096) return static_cast<uint32_t>(cand);
    }
    return 512;
}

} // namespace gpt
