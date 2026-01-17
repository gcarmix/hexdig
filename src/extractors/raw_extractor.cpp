#include "extractor_registration.hpp"
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include "helpers.hpp"
namespace fs = std::filesystem;

class RawExtractor : public BaseExtractor {
public:
    std::string name() const override {
        return "RAW";
    }

    void extract(const std::vector<std::uint8_t>& blob, size_t offset, fs::path extractionPath) override 
    { 
        extractInternal(blob, offset, extractionPath, ".bin");
    } 
    // Overload for raw formats (4 parameters) 
    void extract(const std::vector<std::uint8_t>& blob, size_t offset, fs::path extractionPath, const std::string& extension) 
    { 
        std::string ext = extension; 
        if (!ext.empty() && ext[0] != '.') 
            ext = "." + ext; 
        extractInternal(blob, offset, extractionPath, ext); 
    }
private:
    void extractInternal(const std::vector<std::uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath,
                 const std::string& extension) 
    {
        if (offset >= blob.size())
            return;
        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);


        // Normalize extension
        std::string ext = extension;
        if (!ext.empty() && ext[0] != '.')
            ext = "." + ext;

        // Generate a unique filename
        fs::path outPath;
       
        std::ostringstream name;
        name << "file" << ext;
        outPath = extractionPath / name.str();
            
        

        // Write file
        std::ofstream out(outPath, std::ios::binary);
        if (!out)
            return;

        out.write(reinterpret_cast<const char*>(&blob[offset]),
                  blob.size() - offset);
    }
};

REGISTER_EXTRACTOR(RawExtractor)
