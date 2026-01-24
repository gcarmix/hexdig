#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include "helpers.hpp"
#include "logger.hpp"
namespace fs = std::filesystem;



class SevenZipExtractor : public BaseExtractor {
public:
std::string name() const override { return "7Z"; };

void extract(const std::vector<uint8_t>& blob,
                            size_t offset,
                            fs::path extractionPath) {
   
        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);


        std::ostringstream tempFileName;
        tempFileName << extractionPath.string() << "/decompressed.bin";

        std::ofstream out(tempFileName.str(), std::ios::binary);
        if (!out) {
            std::cerr << "SevenZipExtractor: Failed to write temp file\n";
            return;
        }


        
        size_t dumpSize = blob.size() - offset;
        if(dumpSize > MAX_ANALYZED_FILE_SIZE)
        {
            Logger::error("SevenZipExtractor: File too big to decompress");
            return;
        }

        out.write(reinterpret_cast<const char*>(&blob[offset]), dumpSize);
        out.close();
        
        std::ostringstream cmd;
        cmd << "7z x \"" << tempFileName.str() << "\" -o" << extractionPath << " -y -p\"\"";
        #ifdef _WIN32
        cmd <<" > nul 2>&1";
        Logger::debug("Running: "+cmd.str());
        int result = std::system(cmd.str().c_str());
        #else
        Logger::debug("Running: "+cmd.str());
        cmd <<" > /dev/null 2>&1";
        int result = WEXITSTATUS(std::system(cmd.str().c_str()));
        #endif
        

        
        if (result ==1 || result == 127) {
            Logger::error( "SevenZipExtractor: Extraction failed with code "+ std::to_string(result) + ", please check that 7z executable is installed and available on PATH");
        }
        fs::remove(tempFileName.str());
        //Logger::debug(std::to_string(scanner.recursionDepth));
        
            
        

    }

};

REGISTER_EXTRACTOR(SevenZipExtractor)