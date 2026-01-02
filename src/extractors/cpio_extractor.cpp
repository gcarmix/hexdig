#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include "helpers.hpp"
namespace fs = std::filesystem;

struct CpioHeader {
    std::string magic;
    uint32_t ino, mode, uid, gid, nlink, mtime, filesize;
    uint32_t devmajor, devminor, rdevmajor, rdevminor, namesize, check;
};




class CPIOExtractor : public BaseExtractor {
public:
std::string name() const override { return "CPIO"; };

size_t align4(size_t offset) {
    return (offset + 3) & ~3;
}

uint32_t parse_hex(const char* data, size_t len) {
    std::string hex(data, len);
    return std::stoul(hex, nullptr, 16);
}

CpioHeader read_header(const std::vector<uint8_t>& blob, size_t& offset) {
    if (offset + 110 > blob.size()) throw std::runtime_error("Unexpected end of blob");

    CpioHeader hdr;
    hdr.magic = std::string(reinterpret_cast<const char*>(&blob[offset]), 6);
    if (hdr.magic != "070701") throw std::runtime_error("Unsupported CPIO format");

    offset += 6;
    hdr.ino       = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.mode      = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.uid       = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.gid       = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.nlink     = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.mtime     = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.filesize  = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.devmajor  = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.devminor  = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.rdevmajor = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.rdevminor = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.namesize  = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;
    hdr.check     = parse_hex(reinterpret_cast<const char*>(&blob[offset]), 8); offset += 8;

    return hdr;
}



void extract(const std::vector<uint8_t>& blob,
                            size_t offset,
                            fs::path extractionPath) {
   

    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);

        while (offset < blob.size()) {
        CpioHeader hdr = read_header(blob, offset);

        if (offset + hdr.namesize > blob.size()) throw std::runtime_error("Invalid name size");
        std::string name(reinterpret_cast<const char*>(&blob[offset]), hdr.namesize);
        name = name.substr(0, name.find('\0'));
        offset += hdr.namesize;
        offset = align4(offset);

        if (name == "TRAILER!!!") break;

        std::string full_path =  extractionPath.string()+"/"+ name;
        fs::create_directories(fs::path(full_path).parent_path());

        if ((hdr.mode & 0170000) == 0040000) {
            fs::create_directories(full_path);
        } else if ((hdr.mode & 0170000) == 0100000) {
            if (offset + hdr.filesize > blob.size()) throw std::runtime_error("Invalid file size");
            std::ofstream out(full_path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(&blob[offset]), hdr.filesize);
            out.close();
        }

        offset += hdr.filesize;
        offset = align4(offset);
    }


}
};

REGISTER_EXTRACTOR(CPIOExtractor)