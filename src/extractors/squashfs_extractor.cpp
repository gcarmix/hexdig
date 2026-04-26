#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include "helpers.hpp"
#include "logger.hpp"
#ifndef _WIN32
#include <sys/wait.h>
#endif
namespace fs = std::filesystem;

class SquashFSExtractor : public BaseExtractor {
public:
    std::string name() const override { return "SquashFS"; };
    void extract(const std::vector<uint8_t>& blob, size_t offset, fs::path extractionPath) override {

        extractionPath = extractionPath / fs::path(to_hex(offset));
        fs::create_directories(extractionPath);

        std::string imagePath = extractionPath.string() + "/squashfs.img";
        {
            std::ofstream out(imagePath, std::ios::binary);
            if (!out) {
                Logger::error("SquashFSExtractor: cannot create temporary image file");
                return;
            }
            out.write(reinterpret_cast<const char*>(&blob[offset]), blob.size() - offset);
        }

        // 7-Zip handles SquashFS natively (built into 7z.dll on Windows / the 7zz
        // binary on Unix). Replaces the previous sasquatch dependency, which
        // wasn't available on Windows.
        std::ostringstream cmd;
        cmd << find_7z() << " x \"" << imagePath << "\" -o\"" << extractionPath.string()
            << "\" -y";
#ifdef _WIN32
        cmd << " > nul 2>&1";
#else
        cmd << " > /dev/null 2>&1";
#endif
        Logger::debug("Running: " + cmd.str());
        int result = run_command(cmd.str());

        if (result == 1 || result == 127) {
            Logger::error("SquashFSExtractor: Extraction failed with code "
                          + std::to_string(result)
                          + ", please check that 7z is installed and on PATH "
                            "(or bundle 7z.exe + 7z.dll / 7zz next to the application)");
        }

        fs::remove(imagePath);
    }
};

REGISTER_EXTRACTOR(SquashFSExtractor)