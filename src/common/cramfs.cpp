#include "cramfs.hpp"
#include "helpers.hpp"
CramfsInode parseInode(const std::vector<uint8_t>& b, size_t off, bool le) {
    uint32_t w0 = le ? read_le32(b, off) : read_be32(b, off);
    uint32_t w1 = le ? read_le32(b, off + 4) : read_be32(b, off + 4);
    uint32_t w2 = le ? read_le32(b, off + 8) : read_be32(b, off + 8);

    CramfsInode ino{};
    ino.mode    = (uint16_t)(w0 & 0xFFFF);
    ino.uid     = (uint16_t)((w0 >> 16) & 0xFFFF);
    ino.size    = (uint32_t)(w1 & 0x00FFFFFF);
    ino.gid     = (uint8_t)((w1 >> 24) & 0xFF);
    ino.namelen = (uint8_t)(w2 & 0x3F);
    ino.offset  = (uint32_t)((w2 >> 6) & 0x03FFFFFF);
    return ino;
}

bool isDir(uint16_t mode) {
    // POSIX S_IFDIR = 0x4000
    return (mode & 0xF000) == 0x4000;
}
bool isReg(uint16_t mode) {
    // POSIX S_IFREG = 0x8000
    return (mode & 0xF000) == 0x8000;
}