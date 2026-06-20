#pragma once
//
// lzop (.lzo) container format helpers shared by the LZO parser and extractor.
//
// The lzop file format wraps LZO1X compressed data with a 9-byte magic,
// a header describing the original file, and a sequence of compressed blocks.
// All multi-byte header/block fields are stored big-endian.
//
#include <cstdint>
#include <string>
#include <vector>

// 9-byte lzop magic: \x89 L Z O \0 \r \n \x1a \n
static constexpr uint8_t LZOP_MAGIC[9] =
    {0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a};

// Header/block flags (subset relevant to parsing the stream layout)
static constexpr uint32_t LZOP_F_ADLER32_D    = 0x00000001UL;
static constexpr uint32_t LZOP_F_ADLER32_C    = 0x00000002UL;
static constexpr uint32_t LZOP_F_H_EXTRA_FIELD= 0x00000040UL;
static constexpr uint32_t LZOP_F_CRC32_D      = 0x00000100UL;
static constexpr uint32_t LZOP_F_CRC32_C      = 0x00000200UL;
static constexpr uint32_t LZOP_F_H_FILTER     = 0x00000800UL;
static constexpr uint32_t LZOP_F_H_CRC32      = 0x00001000UL;

// Header version at/after which extra fields (version_needed, level, mtime_high)
// are present.
static constexpr uint16_t LZOP_VERSION_0940 = 0x0940;

struct LzopHeader {
    uint16_t version       = 0;
    uint16_t libVersion    = 0;
    uint16_t versionNeeded = 0;
    uint8_t  method        = 0;
    uint8_t  level         = 0;
    uint32_t flags         = 0;
    uint32_t filter        = 0;
    uint32_t mode          = 0;
    uint32_t mtimeLow      = 0;
    uint32_t mtimeHigh     = 0;
    std::string name;       // original file name (may be empty)
    size_t   blockStart    = 0; // offset of the first compressed block
};

// Bounds-checked big-endian readers used while walking the stream.
static inline bool lzop_rd16(const std::vector<uint8_t>& b, size_t& p, uint16_t& v) {
    if (p + 2 > b.size()) return false;
    v = (uint16_t)((b[p] << 8) | b[p + 1]);
    p += 2;
    return true;
}
static inline bool lzop_rd32(const std::vector<uint8_t>& b, size_t& p, uint32_t& v) {
    if (p + 4 > b.size()) return false;
    v = ((uint32_t)b[p] << 24) | ((uint32_t)b[p + 1] << 16) |
        ((uint32_t)b[p + 2] << 8) | (uint32_t)b[p + 3];
    p += 4;
    return true;
}
static inline bool lzop_rd8(const std::vector<uint8_t>& b, size_t& p, uint8_t& v) {
    if (p + 1 > b.size()) return false;
    v = b[p++];
    return true;
}

// Returns true if the lzop magic is present at the given offset.
static inline bool is_lzop_magic(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + sizeof(LZOP_MAGIC) > blob.size()) return false;
    for (size_t i = 0; i < sizeof(LZOP_MAGIC); i++)
        if (blob[offset + i] != LZOP_MAGIC[i]) return false;
    return true;
}

// Parse the lzop file header at `offset` (which must point at the magic).
// On success fills `h` and sets h.blockStart to the offset of the first block.
static inline bool parse_lzop_header(const std::vector<uint8_t>& blob,
                                     size_t offset, LzopHeader& h) {
    if (!is_lzop_magic(blob, offset)) return false;
    size_t p = offset + sizeof(LZOP_MAGIC);

    if (!lzop_rd16(blob, p, h.version)) return false;
    if (!lzop_rd16(blob, p, h.libVersion)) return false;
    if (h.version >= LZOP_VERSION_0940)
        if (!lzop_rd16(blob, p, h.versionNeeded)) return false;
    if (!lzop_rd8(blob, p, h.method)) return false;
    if (h.version >= LZOP_VERSION_0940)
        if (!lzop_rd8(blob, p, h.level)) return false;
    if (!lzop_rd32(blob, p, h.flags)) return false;
    if (h.flags & LZOP_F_H_FILTER)
        if (!lzop_rd32(blob, p, h.filter)) return false;
    if (!lzop_rd32(blob, p, h.mode)) return false;
    if (!lzop_rd32(blob, p, h.mtimeLow)) return false;
    if (h.version >= LZOP_VERSION_0940)
        if (!lzop_rd32(blob, p, h.mtimeHigh)) return false;

    uint8_t nameLen = 0;
    if (!lzop_rd8(blob, p, nameLen)) return false;
    if (nameLen) {
        if (p + nameLen > blob.size()) return false;
        h.name.assign(reinterpret_cast<const char*>(&blob[p]), nameLen);
        p += nameLen;
    }

    uint32_t headerChecksum = 0;          // CRC32/Adler32 of the header
    if (!lzop_rd32(blob, p, headerChecksum)) return false;

    h.blockStart = p;
    return true;
}
