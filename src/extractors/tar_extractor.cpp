#include "extractor_registration.hpp"
#include "base_extractor.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>
#include "logger.hpp"
#include "helpers.hpp"

namespace fs = std::filesystem;

class TARExtractor : public BaseExtractor {
public:
    void extract(const std::vector<uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override;

    std::string name() const override {
        return "TAR";
    }
};

static std::string read_string(const uint8_t* buf, size_t len) {
    size_t n = 0;
    while (n < len && buf[n] != 0) n++;
    return std::string(reinterpret_cast<const char*>(buf), n);
}

static size_t read_octal(const uint8_t* buf, size_t len) {
    std::string s(reinterpret_cast<const char*>(buf), len);
    size_t end = s.find_last_not_of(" \0", std::string::npos);
    if (end != std::string::npos) s = s.substr(0, end + 1);
    size_t val = 0;
    std::stringstream ss;
    ss << std::oct << s;
    ss >> val;
    return val;
}

static std::string sanitize_path(const std::string& raw) {
    // Force to relative: strips any root_name ("C:") and root_directory ("/")
    // so a leading slash in the tar entry can't escape the extraction dir
    // when used with operator/.
    fs::path rel = fs::path(raw).relative_path();

    fs::path safe;
    for (auto& part : rel) {
        std::string s = part.string();
        if (s.empty() || s == "." || s == "..") continue;
        safe /= s;
    }
    return safe.string();
}

void TARExtractor::extract(const std::vector<uint8_t>& blob,
                           size_t offset,
                           fs::path extractionPath) {
    if (offset + 512 > blob.size()) return;

    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);
    size_t pos = offset;

    while (pos + 512 <= blob.size()) {
    const uint8_t* hdr = &blob[pos];

    // End of archive: two consecutive zero blocks
    bool zero1 = std::all_of(hdr, hdr+512, [](uint8_t b){ return b==0; });
    bool zero2 = (pos+1024 <= blob.size()) &&
                 std::all_of(&blob[pos+512], &blob[pos+1024], [](uint8_t b){ return b==0; });
    if (zero1 && zero2) {
        //std::cout << "TARExtractor: End of archive\n";
        break;
    }

    std::string rawName = read_string(hdr, 100);
    std::string safeName = sanitize_path(rawName);
    Logger::debug(safeName);
    size_t size = read_octal(hdr + 124, 12);
    char typeflag = hdr[156];

    fs::path outPath = extractionPath / safeName;
    fs::create_directories(outPath.parent_path());

    if (typeflag == '0' || typeflag == '\0') {
        std::ofstream out(outPath, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(&blob[pos + 512]), size);
            //std::cout << "Extracted file: " << outPath << " (" << size << " bytes)\n";
        }
    } else if (typeflag == '5') {
        fs::create_directories(outPath);
        //std::cout << "Created directory: " << outPath << "\n";
    } else if (typeflag == '2') {
        std::string linkname = read_string(hdr + 157, 100);
        std::ofstream out(outPath.string() + ".symlink");
        out << "Symlink to: " << linkname << "\n";
        //std::cout << "Logged symlink: " << outPath << " -> " << linkname << "\n";
    } else {
        std::ofstream out(outPath);
        //std::cout << "Created placeholder for special file: " << outPath << "\n";
    }

    size_t blocks = (size + 511) / 512;
    pos += 512 + blocks * 512;
}



}

REGISTER_EXTRACTOR(TARExtractor)