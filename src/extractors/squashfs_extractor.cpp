#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <filesystem>
#include "helpers.hpp"
#include "logger.hpp"
namespace fs = std::filesystem;
class SquashFSExtractor : public BaseExtractor {
public:
    std::string name() const override { return "SquashFS"; };
    void extract(const std::vector<uint8_t>& blob, size_t offset, fs::path extractionPath) override {

        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);
        
        Logger::debug(extractionPath.string());
        std::string imagePath = extractionPath.string() + "/squashfs.img";
        std::ofstream out(imagePath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(&blob[offset]), blob.size() - offset);
        out.close();

        std::string cmd = "sasquatch -d " + extractionPath.string() + " " + imagePath + " > /dev/null 2>&1";
        int result = std::system(cmd.c_str());
        fs::remove(imagePath);
        /*if (result != 0) {
            std::cerr << "[SquashFSExtractor] sasquatch failed at offset " << offset << "\n";
            return;
        }*/



    }
};

REGISTER_EXTRACTOR(SquashFSExtractor)