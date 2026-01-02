#pragma once
#include <cstdint>
#include <vector>
struct CramfsInode {
    uint16_t mode;      // file type + permissions
    uint16_t uid;
    uint32_t size;      // 24-bit
    uint8_t  gid;       // 8-bit
    uint8_t  namelen;   // 6-bit
    uint32_t offset;    // 26-bit
};

CramfsInode parseInode(const std::vector<uint8_t>& b, size_t off, bool le);
bool isDir(uint16_t mode);
bool isReg(uint16_t mode);