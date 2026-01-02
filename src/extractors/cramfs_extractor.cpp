
#include <zlib.h>
#include <iostream>
#include "extractor_registration.hpp"
#include "base_extractor.hpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include "cramfs.hpp"
#include "helpers.hpp"

namespace fs = std::filesystem;



class CramFSExtractor : public BaseExtractor {
public:
    std::string name() const override { return "CramFS"; }

    void extract(const std::vector<std::uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override;
};

// Decompress a single CramFS block (usually 4KB page)
static std::vector<uint8_t> decompressBlock(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(4096);
    z_stream strm{};
    strm.next_in = const_cast<Bytef*>(data);
    strm.avail_in = len;
    strm.next_out = out.data();
    strm.avail_out = out.size();

    if (inflateInit(&strm) != Z_OK) return {};
    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) return {};
    out.resize(out.size() - strm.avail_out);
    return out;
}

static void extractInode(const std::vector<uint8_t>& blob, size_t base, bool le,
                         const CramfsInode& ino, const std::string& name,
                         const fs::path& outDir) {
    if (isDir(ino.mode)) {
        fs::create_directories(outDir / name);
        size_t cursor = base + ino.offset;
        size_t end = base + ino.size;
        while (cursor + 12 <= end) {
            CramfsInode child = parseInode(blob, cursor, le);
            cursor += 12;
            std::string childName;
            for (int i = 0; i < child.namelen; i++) {
                childName.push_back((char)blob[cursor++]);
            }
            extractInode(blob, base, le, child, childName, outDir / name);
        }
    } else if (isReg(ino.mode)) {
        fs::create_directories(outDir);
        std::ofstream ofs(outDir / name, std::ios::binary);
        size_t cursor = base + ino.offset;
        size_t remaining = ino.size;
        while (remaining > 0 && cursor + 4 <= blob.size()) {
            uint32_t blockLen = le ? read_le32(blob, cursor) : read_be32(blob, cursor);
            cursor += 4;
            if (cursor + blockLen > blob.size()) break;
            auto block = decompressBlock(&blob[cursor], blockLen);
            cursor += blockLen;
            ofs.write((const char*)block.data(), block.size());
            if (block.size() > remaining) break;
            remaining -= block.size();
        }
    }
}

void CramFSExtractor::extract(const std::vector<std::uint8_t>& blob,
                              size_t offset,
                              fs::path extractionPath) {
    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);
    // Detect endianness
    bool le = true;
    uint32_t magicLE = read_le32(blob, offset);
    if (magicLE != 0x28CD3D45u && magicLE != 0x453DCD28u) le = false;

    // Root inode at offset + 0x40
    CramfsInode root = parseInode(blob, offset + 0x40, le);
    std::string rootName;
    if (root.namelen) {
        for (int i = 0; i < root.namelen; i++) {
            rootName.push_back((char)blob[offset + 0x40 + 12 + i]);
        }
    } else {
        rootName = "root";
    }

    extractInode(blob, offset, le, root, rootName, extractionPath);
}

REGISTER_EXTRACTOR(CramFSExtractor)