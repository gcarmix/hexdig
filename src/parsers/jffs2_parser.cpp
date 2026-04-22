#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>
#include <zlib.h>


class JFFS2Parser : public BaseParser {
public:
    std::string name() const override { return "JFFS2"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;
};

static constexpr uint16_t JFFS2_MAGIC     = 0x1985;
static constexpr uint16_t JFFS2_OLD_MAGIC = 0x1984;
static constexpr uint32_t DEFAULT_ERASEBLOCK = 0x20000; // 128 KB typical

// Known JFFS2 nodetypes (with compat + accurate bits). A random 16-bit value
// has ~1-in-9k odds of hitting this set, which on its own is not strong
// enough to reject a false positive — but combined with the header CRC it
// is overwhelming.
//   DIRENT      = INCOMPAT | ACCURATE | 1 = 0xE001
//   INODE       = INCOMPAT | ACCURATE | 2 = 0xE002
//   CLEANMARKER = RWCOMPAT_DEL | ACCURATE | 3 = 0x2003
//   PADDING     = RWCOMPAT_DEL | ACCURATE | 4 = 0x2004
//   SUMMARY     = RWCOMPAT_DEL | ACCURATE | 6 = 0x2006
//   XATTR       = INCOMPAT | ACCURATE | 8 = 0xE008
//   XREF        = INCOMPAT | ACCURATE | 9 = 0xE009
static bool isKnownJffs2Nodetype(uint16_t nt) {
    switch (nt) {
        case 0xE001: case 0xE002: case 0x2003:
        case 0x2004: case 0x2006: case 0xE008:
        case 0xE009:
            return true;
    }
    return false;
}

// JFFS2 uses CRC-32 with init=0 and no final XOR. zlib's crc32() is the
// standard CRC-32 (init=0, final XOR 0xFFFFFFFF, with an implicit unxor
// of the seed), so seeding with 0xFFFFFFFF and xor'ing the result with
// 0xFFFFFFFF cancels both inversions and gives the raw JFFS2 form — the
// same formula the extractor already uses.
static uint32_t jffs2HdrCrc(const uint8_t* data, size_t len) {
    uint32_t crc = ::crc32(0xFFFFFFFFu, data, static_cast<uInt>(len));
    return crc ^ 0xFFFFFFFFu;
}

static inline uint32_t pad4(uint32_t x) { return (x + 3) & ~3u; }

#pragma pack(push, 1)
struct Jffs2RawNodeRef {
    uint16_t magic;
    uint16_t nodetype;
    uint32_t totlen;
    uint32_t hdr_crc;
};
#pragma pack(pop)

static bool validateJffs2Node(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + sizeof(Jffs2RawNodeRef) > blob.size())
        return false;

    auto* h = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[offset]);

    if (h->magic != JFFS2_MAGIC && h->magic != JFFS2_OLD_MAGIC)
        return false;
    if (!isKnownJffs2Nodetype(h->nodetype))
        return false;
    if (h->totlen < sizeof(Jffs2RawNodeRef))
        return false;
    if (h->totlen > DEFAULT_ERASEBLOCK)
        return false;
    if (offset + h->totlen > blob.size())
        return false;

    // The header CRC covers the first 8 bytes (magic + nodetype + totlen).
    return jffs2HdrCrc(&blob[offset], 8) == h->hdr_crc;
}

bool JFFS2Parser::match(const std::vector<uint8_t>& blob, size_t offset) {
    return validateJffs2Node(blob, offset);
}

ScanResult JFFS2Parser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    ScanResult r;
    r.offset = offset;
    r.type = "JFFS2";
    r.extractorType = "JFFS2";
    r.length = 0;
    r.isValid = false;

    // Require a run of CRC-valid nodes walked via totlen before accepting.
    // Three consecutive 32-bit-CRC matches at totlen-predicted offsets is
    // effectively unattainable in random data.
    static constexpr int MIN_NODES = 3;

    size_t pos = offset;
    size_t lastNodeEnd = pos;
    int validNodes = 0;

    while (validateJffs2Node(blob, pos)) {
        auto* h = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[pos]);
        lastNodeEnd = pos + h->totlen;
        pos += pad4(h->totlen);
        validNodes++;
    }

    if (validNodes < MIN_NODES) {
        r.info = "JFFS2 header present but no valid node chain";
        return r;
    }

    // Keep walking across eraseblocks, tolerating padding gaps: within each
    // eraseblock, rescan 4-byte-aligned for the next valid node. Stop after
    // two eraseblocks produce no valid node.
    size_t emptyEBs = 0;
    const size_t MAX_EMPTY = 2;

    while (pos + sizeof(Jffs2RawNodeRef) <= blob.size()) {
        size_t ebEnd = ((pos / DEFAULT_ERASEBLOCK) + 1) * DEFAULT_ERASEBLOCK;
        if (ebEnd > blob.size()) ebEnd = blob.size();

        size_t p = (pos + 3) & ~size_t(3);
        bool found = false;
        while (p + sizeof(Jffs2RawNodeRef) <= ebEnd) {
            if (validateJffs2Node(blob, p)) {
                auto* h = reinterpret_cast<const Jffs2RawNodeRef*>(&blob[p]);
                lastNodeEnd = p + h->totlen;
                pos = p + pad4(h->totlen);
                validNodes++;
                found = true;
                break;
            }
            p += 4;
        }
        if (!found) {
            emptyEBs++;
            if (emptyEBs >= MAX_EMPTY) break;
            pos = ebEnd;
        } else {
            emptyEBs = 0;
        }
    }

    // Round length up to the next eraseblock boundary relative to `offset`.
    size_t rel = lastNodeEnd - offset;
    size_t aligned = ((rel + DEFAULT_ERASEBLOCK - 1) / DEFAULT_ERASEBLOCK)
                     * DEFAULT_ERASEBLOCK;
    size_t end = offset + aligned;
    if (end > blob.size()) end = blob.size();

    r.length = end - offset;
    r.isValid = true;

    std::ostringstream info;
    info << "JFFS2 filesystem, " << validNodes << " valid nodes";
    r.info = info.str();
    return r;
}

REGISTER_PARSER(JFFS2Parser)
