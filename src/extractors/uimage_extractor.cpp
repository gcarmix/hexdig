#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include "logger.hpp"
#include "helpers.hpp"

namespace fs = std::filesystem;

class UImageExtractor : public BaseExtractor {
public:
std::string name() const override { return "UIMAGE"; };

void extract(const std::vector<uint8_t>& blob,
                              size_t offset,
                              fs::path extractionPath) {
    // The uImage header is 64 bytes; we then read the image name field
    // (bytes 32–63) and slice the payload starting at byte 64. All three
    // require the full header to be present.
    if (offset + 64 > blob.size()) return;
    const uint8_t UIMAGE_MAGIC[] = {0x27, 0x05, 0x19, 0x56};  // Replace with actual magic
    const size_t MAGIC_SIZE = sizeof(UIMAGE_MAGIC);

    // Check binary signature
    for (size_t i = 0; i < MAGIC_SIZE; ++i) {
        if (blob[offset + i] != UIMAGE_MAGIC[i]) {
            Logger::error("UImageExtractor: Invalid magic header");
            return;
        }
    }
    // Extract image name (bytes 32–63)
    std::string imageName;
    for (size_t i = 0; i < 32; ++i) {
        char c = static_cast<char>(blob[offset + 32 + i]);
        if (c == '\0') break;
        imageName += c;
    }
    if (imageName.empty()) imageName = "uimage_payload";

    // Payload starts right after the 64-byte header and runs to end of blob.
    std::vector<uint8_t> payload(blob.begin() + offset + 64, blob.end());

    // Build output folder
    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);

    // Get original filename from scanner context


   
    fs::path outPath = extractionPath / (imageName + ".bin");
    std::ofstream outFile(outPath, std::ios::binary);
    if (outFile.is_open()) {
        outFile.write(reinterpret_cast<const char*>(payload.data()), payload.size());
        outFile.close();
    }
}

};

REGISTER_EXTRACTOR(UImageExtractor)