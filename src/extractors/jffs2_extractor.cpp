#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include "helpers.hpp"
#include "logger.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <sys/stat.h>
#include <zlib.h>
#include <lzma.h>
#include <lzo/lzo1x.h>

namespace fs = std::filesystem;

// ---- Constants copied from Jefferson ----

static constexpr uint16_t JFFS2_OLD_MAGIC_BITMASK = 0x1984;
static constexpr uint16_t JFFS2_MAGIC_BITMASK     = 0x1985;

static constexpr uint8_t JFFS2_COMPR_NONE  = 0x00;
static constexpr uint8_t JFFS2_COMPR_ZERO  = 0x01;
static constexpr uint8_t JFFS2_COMPR_RTIME = 0x02;
static constexpr uint8_t JFFS2_COMPR_RUBINMIPS = 0x03;
static constexpr uint8_t JFFS2_COMPR_COPY  = 0x04;
static constexpr uint8_t JFFS2_COMPR_DYNRUBIN = 0x05;
static constexpr uint8_t JFFS2_COMPR_ZLIB  = 0x06;
static constexpr uint8_t JFFS2_COMPR_LZO   = 0x07;
static constexpr uint8_t JFFS2_COMPR_LZMA  = 0x08;

// Compatibility flags
static constexpr uint16_t JFFS2_COMPAT_MASK       = 0xC000;
static constexpr uint16_t JFFS2_NODE_ACCURATE     = 0x2000;
static constexpr uint16_t JFFS2_FEATURE_INCOMPAT  = 0xC000;
static constexpr uint16_t JFFS2_FEATURE_ROCOMPAT  = 0x8000;
static constexpr uint16_t JFFS2_FEATURE_RWCOMPAT_COPY   = 0x4000;
static constexpr uint16_t JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000;

// Nodetypes
static constexpr uint16_t JFFS2_NODETYPE_DIRENT =
    JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1;
static constexpr uint16_t JFFS2_NODETYPE_INODE =
    JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2;
static constexpr uint16_t JFFS2_NODETYPE_CLEANMARKER =
    JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3;
static constexpr uint16_t JFFS2_NODETYPE_PADDING =
    JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4;
static constexpr uint16_t JFFS2_NODETYPE_SUMMARY =
    JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6;

// PAD macro
static inline uint32_t PAD(uint32_t x) {
    return (x + 3) & ~3u;
}

// CRC like Jefferson
static uint32_t mtd_crc(const uint8_t* data, size_t len) {
    uint32_t crc = ::crc32(0xFFFFFFFFu, data, static_cast<uInt>(len));
    return (crc ^ 0xFFFFFFFFu) & 0xFFFFFFFFu;
}

// ---- Structs matching your CSTRUCT_DEFINITIONS ----

#pragma pack(push, 1)
struct Jffs2_unknown_node {
    uint16_t magic;
    uint16_t nodetype;
    uint32_t totlen;
    uint32_t hdr_crc;
};

struct Jffs2_raw_dirent {
    uint16_t magic;
    uint16_t nodetype;
    uint32_t totlen;
    uint32_t hdr_crc;
    uint32_t pino;
    uint32_t version;
    uint32_t ino;
    uint32_t mctime;
    uint8_t  nsize;
    uint8_t  type;
    uint8_t  unused[2];
    uint32_t node_crc;
    uint32_t name_crc;
    // name[] follows
};

struct Jffs2_raw_inode {
    uint16_t magic;
    uint16_t nodetype;
    uint32_t totlen;
    uint32_t hdr_crc;
    uint32_t ino;
    uint32_t version;
    uint32_t mode;
    uint16_t uid;
    uint16_t gid;
    uint32_t isize;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    uint32_t offset;
    uint32_t csize;
    uint32_t dsize;
    uint8_t  compr;
    uint8_t  usercompr;
    uint16_t flags;
    uint32_t data_crc;
    uint32_t node_crc;
    // data[] follows
};
#pragma pack(pop)

// ---- In-memory structures ----

struct InodeChunk {
    uint32_t offset;
    uint32_t version;
    std::vector<uint8_t> data;
};

struct Inode {
    uint32_t ino;
    uint32_t isize;
    uint32_t mode;
    std::vector<InodeChunk> chunks;
};

struct Dirent {
    uint32_t ino;
    uint32_t pino;
    uint32_t version;
    std::string name;
};

static bool rtime_decompress(const uint8_t* data_in,
                             uint32_t src_len,
                             uint8_t* dst,
                             uint32_t destlen)
{
    // positions[value] = last output position where this byte occurred
    uint32_t positions[256];
    std::memset(positions, 0, sizeof(positions));

    uint32_t outpos = 0;
    uint32_t pos = 0;

    while (outpos < destlen) {
        if (pos + 2 > src_len)
            return false; // malformed input

        uint8_t value = data_in[pos++];
        dst[outpos++] = value;

        uint8_t repeat = data_in[pos++];

        uint32_t backoffs = positions[value];
        positions[value] = outpos;

        if (repeat) {
            // If backoffs+repeat overlaps the current output position,
            // copy byte-by-byte (like Python version)
            if (backoffs + repeat >= outpos) {
                while (repeat--) {
                    if (backoffs >= outpos) return false;
                    if (outpos >= destlen) return false;
                    dst[outpos++] = dst[backoffs++];
                }
            } else {
                // Otherwise copy as a block
                if (backoffs + repeat > destlen) return false;
                if (outpos + repeat > destlen) return false;

                std::memcpy(dst + outpos, dst + backoffs, repeat);
                outpos += repeat;
            }
        }
    }

    return true;
}




static bool lzo_decompress(const uint8_t* src,
                           uint32_t src_len,
                           std::vector<uint8_t>& out,
                           uint32_t expected_size)
{
    // Initialize LZO (required once per process)
    static bool initialized = false;
    if (!initialized) {
        if (lzo_init() != LZO_E_OK)
            return false;
        initialized = true;
    }

    out.resize(expected_size);

    lzo_uint out_len = expected_size;
    int r = lzo1x_decompress_safe(
        src,
        src_len,
        out.data(),
        &out_len,
        nullptr
    );

    if (r != LZO_E_OK)
        return false;

    // Jefferson expects EXACT dsize bytes
    if (out_len != expected_size)
        return false;

    return true;
}




static bool lzma_decompress(const uint8_t* src,
                            uint32_t src_len,
                            uint8_t* dst,
                            uint32_t dst_len)
{
    // Jefferson constants
    const uint8_t lc = 0;
    const uint8_t lp = 0;
    const uint8_t pb = 0;
    const uint32_t dict_size = 0x2000;

    // Build LZMA header: <BIQ  (little-endian)
    //   B  = properties
    //   I  = dict size
    //   Q  = uncompressed size
    uint8_t header[13];
    header[0] = (pb * 5 + lp) * 9 + lc;

    // dict size (uint32 LE)
    header[1] = (dict_size >> 0) & 0xFF;
    header[2] = (dict_size >> 8) & 0xFF;
    header[3] = (dict_size >> 16) & 0xFF;
    header[4] = (dict_size >> 24) & 0xFF;

    // uncompressed size (uint64 LE)
    uint64_t outlen64 = dst_len;
    for (int i = 0; i < 8; i++)
        header[5 + i] = (outlen64 >> (8 * i)) & 0xFF;

    // Concatenate header + compressed data
    std::vector<uint8_t> full;
    full.reserve(13 + src_len);
    full.insert(full.end(), header, header + 13);
    full.insert(full.end(), src, src + src_len);

    // Prepare LZMA stream
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK)
        return false;

    strm.next_in = full.data();
    strm.avail_in = full.size();

    strm.next_out = dst;
    strm.avail_out = dst_len;

    ret = lzma_code(&strm, LZMA_FINISH);

    lzma_end(&strm);

    return (ret == LZMA_STREAM_END);
}

// ---- Helper: safe path ----

static bool is_safe_path(const fs::path& base, const fs::path& real_path) {
    auto b = fs::weakly_canonical(base);
    auto r = fs::weakly_canonical(real_path);
    return std::mismatch(b.begin(), b.end(), r.begin(), r.end()).first == b.end();
}

// ---- The extractor ----

class Jffs2Extractor : public BaseExtractor {
public:
    std::string name() const override { return "JFFS2"; }

    void extract(const std::vector<uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override
    {
        if (offset >= blob.size()) {
            Logger::error("JFFS2: offset beyond blob size");
            return;
        }

        const uint8_t* base = blob.data() + offset;
        size_t len = blob.size() - offset;

        // Determine endianness like Jefferson (we only support little here)
        uint16_t magic = *reinterpret_cast<const uint16_t*>(base);
        if (magic != JFFS2_MAGIC_BITMASK && magic != JFFS2_OLD_MAGIC_BITMASK) {
            Logger::error("JFFS2: magic mismatch at offset");
            return;
        }

        fs::create_directories(extractionPath);
        extractionPath /= fs::path(to_hex(offset));
        fs::create_directories(extractionPath);

        // Scan filesystem
        std::map<uint32_t, std::vector<Inode>> inode_map;
        std::map<uint32_t, Dirent> dirent_map;

        scan_fs(base, len, inode_map, dirent_map);

        // Dump filesystem
        dump_fs(inode_map, dirent_map, extractionPath);
    }

private:
    void scan_fs(const uint8_t* content, size_t length,
                 std::map<uint32_t, std::vector<Inode>>& inode_map,
                 std::map<uint32_t, Dirent>& dirent_map)
    {
        size_t pos = 0;
        const size_t unk_size = sizeof(Jffs2_unknown_node);

        while (true) {
            if (pos + unk_size >= length) break;

            // Find magic (like content.find in Python)
            bool found = false;
            for (; pos + unk_size < length; ++pos) {
                uint16_t m = *reinterpret_cast<const uint16_t*>(content + pos);
                if (m == JFFS2_MAGIC_BITMASK || m == JFFS2_OLD_MAGIC_BITMASK) {
                    found = true;
                    break;
                }
            }
            if (!found) break;

            auto* unk = reinterpret_cast<const Jffs2_unknown_node*>(content + pos);
            // Verify header CRC
            if (pos + unk_size > length) { pos++; continue; }
            uint32_t comp_hdr_crc = mtd_crc(content + pos, unk_size - 4);
            if (comp_hdr_crc != unk->hdr_crc) {
                pos++;
                continue;
            }

            uint32_t totlen = unk->totlen;
            size_t node_offset = pos;
            pos += PAD(totlen);
            if (node_offset + totlen > length) continue;

            uint16_t nodetype = unk->nodetype;

            if (nodetype == JFFS2_NODETYPE_DIRENT) {
                parse_dirent(content, length, node_offset, dirent_map);
            } else if (nodetype == JFFS2_NODETYPE_INODE) {
                parse_inode(content, length, node_offset, inode_map);
            } else {
                // CLEANMARKER, PADDING, SUMMARY, etc. are ignored
            }
        }
    }

    void parse_dirent(const uint8_t* content, size_t length,
                      size_t offset,
                      std::map<uint32_t, Dirent>& dirent_map)
    {
        if (offset + sizeof(Jffs2_raw_dirent) > length) return;
        auto* de = reinterpret_cast<const Jffs2_raw_dirent*>(content + offset);

        size_t name_off = offset + sizeof(Jffs2_raw_dirent);
        if (name_off + de->nsize > length) return;

        std::string name(reinterpret_cast<const char*>(content + name_off),
                         de->nsize);

        // CRC checks like Jefferson
        uint32_t node_crc_calc = mtd_crc(content + offset,
                                         sizeof(Jffs2_raw_dirent) - 8);
        uint32_t name_crc_calc = mtd_crc(reinterpret_cast<const uint8_t*>(name.data()),
                                         name.size());
        if (node_crc_calc != de->node_crc) {
            // Jefferson prints but still uses it
        }
        if (name_crc_calc != de->name_crc) {
            // Jefferson prints but still uses it
        }

        Dirent d;
        d.ino = de->ino;
        d.pino = de->pino;
        d.version = de->version;
        d.name = name;

        auto it = dirent_map.find(d.ino);
        if (it == dirent_map.end() || d.version > it->second.version) {
            dirent_map[d.ino] = d;
        }
    }

    void parse_inode(const uint8_t* content, size_t length,
                     size_t offset,
                     std::map<uint32_t, std::vector<Inode>>& inode_map)
    {
        if (offset + sizeof(Jffs2_raw_inode) > length) return;
        auto* ino = reinterpret_cast<const Jffs2_raw_inode*>(content + offset);

        size_t header_size = sizeof(Jffs2_raw_inode);
        size_t data_off = offset + header_size;
        if (data_off > length) return;

        size_t max_data = offset + ino->totlen;
        if (max_data > length) max_data = length;
        if (data_off > max_data) return;

        size_t csize = ino->csize;
        if (data_off + csize > max_data) csize = max_data - data_off;

        const uint8_t* node_data = content + data_off;
        std::vector<uint8_t> data;

        try {
            if (ino->compr == JFFS2_COMPR_NONE) {
                data.assign(node_data, node_data + csize);
            } else if (ino->compr == JFFS2_COMPR_ZERO) {
                data.assign(ino->dsize, 0x00);
            } else if (ino->compr == JFFS2_COMPR_ZLIB) {
                data.resize(ino->dsize);
                uLongf destLen = ino->dsize;
                if (uncompress(data.data(), &destLen, node_data, csize) != Z_OK)
                    data.assign(ino->dsize, 0x00);
            } else if (ino->compr == JFFS2_COMPR_RTIME) {
                data.resize(ino->dsize);
                if (!rtime_decompress(node_data, csize, data.data(), ino->dsize))
                    data.assign(ino->dsize, 0x00);
            } else if (ino->compr == JFFS2_COMPR_LZMA) {
                data.resize(ino->dsize);
                if (!lzma_decompress(node_data, csize, data.data(), ino->dsize))
                    data.assign(ino->dsize, 0x00);
            } else if (ino->compr == JFFS2_COMPR_LZO) {
                if (!lzo_decompress(node_data, csize, data, ino->dsize))

                    data.assign(ino->dsize, 0x00);
            } else {
                // Unknown compression: keep raw
                data.assign(node_data, node_data + csize);
            }
        } catch (...) {
            data.assign(ino->dsize, 0x00);
        }

        // CRC checks like Jefferson
        uint32_t node_crc_calc = mtd_crc(content + offset,
                                         header_size - 8);
        uint32_t data_crc_calc = mtd_crc(node_data, csize);
        (void)node_crc_calc;
        (void)data_crc_calc;

        InodeChunk chunk;
        chunk.offset = ino->offset;
        chunk.version = ino->version;
        chunk.data = std::move(data);

        Inode inode;
        inode.ino = ino->ino;
        inode.isize = ino->isize;
        inode.mode = ino->mode;
        inode.chunks.push_back(std::move(chunk));

        inode_map[ino->ino].push_back(std::move(inode));
    }

    static bool sort_version(const Inode& a, const Inode& b) {
        return a.chunks.front().version < b.chunks.front().version;
    }

    void dump_fs(std::map<uint32_t, std::vector<Inode>>& inode_map,
                 std::map<uint32_t, Dirent>& dirent_map,
                 const fs::path& target_root)
    {
        // Build node_dict like Jefferson
        std::map<uint32_t, Dirent> node_dict = dirent_map;

        for (auto& [ino, dirent] : dirent_map) {
            auto it = inode_map.find(ino);
            if (it != inode_map.end()) {
                auto& vec = it->second;
                std::sort(vec.begin(), vec.end(), sort_version);
            }
        }

        for (auto& [ino, dirent] : dirent_map) {
            // Build path by walking parents
            uint32_t pino = dirent.pino;
            std::vector<Dirent> parents;
            for (int i = 0; i < 100; ++i) {
                auto it = node_dict.find(pino);
                if (it == node_dict.end()) break;
                parents.push_back(it->second);
                pino = it->second.pino;
            }
            std::reverse(parents.begin(), parents.end());

            std::vector<std::string> parts;
            for (auto& p : parents) parts.push_back(p.name);
            parts.push_back(dirent.name);

            fs::path rel;
            for (auto& s : parts) rel /= s;

            fs::path target_path = fs::weakly_canonical(target_root / rel);
            if (!is_safe_path(target_root, target_path)) {
                Logger::error("JFFS2: path traversal attempt, skipping " + target_path.string());
                continue;
            }

            auto it_inodes = inode_map.find(ino);
            if (it_inodes == inode_map.end()) continue;
            auto& inodes = it_inodes->second;

            for (auto& inode : inodes) {
                mode_t mode = static_cast<mode_t>(inode.mode);

                if (S_ISDIR(mode)) {
                    if (!fs::exists(target_path))
                        fs::create_directories(target_path);
                } else if (S_ISREG(mode)) {
                    if (!fs::exists(target_path)) {
                        fs::create_directories(target_path.parent_path());
                        std::ofstream fd(target_path, std::ios::binary);
                        if (!fd) break;
                        // write chunks in order
                        for (auto& in : inodes) {
                            for (auto& ch : in.chunks) {
                                fd.seekp(ch.offset);
                                fd.write(reinterpret_cast<const char*>(ch.data.data()),
                                         ch.data.size());
                            }
                        }
                    }
                    ::chmod(target_path.c_str(), mode & 07777);
                    break;
                } else if (S_ISLNK(mode)) {
                    // Jefferson writes symlink target from inode.data
                    // We skip for now or you can implement if needed.
                } else {
                    // Other types (devices, fifo, sock) skipped
                }
            }
        }
    }
};

REGISTER_EXTRACTOR(Jffs2Extractor)
