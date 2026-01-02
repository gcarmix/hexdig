#include "parser_registration.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>
#include "../utils/helpers.hpp"
class UImageParser : public BaseParser {
public:
    std::string name() const override { return "UImage"; }
    bool match(const std::vector<uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override;
private:
std::string get_os_name(uint8_t os);
std::string get_arch_name(uint8_t arch);
std::string get_compression_type(uint8_t comp);
std::string get_image_type(uint8_t type) ;
};

static constexpr uint32_t UIMAGE_MAGIC = 0x27051956;

std::string UImageParser::get_os_name(uint8_t os) {
    switch (os) {
        case 0: return "Invalid";
        case 1: return "OpenBSD";
        case 2: return "NetBSD";
        case 3: return "FreeBSD";
        case 4: return "4.4BSD";
        case 5: return "Linux";
        case 6: return "SVR4";
        case 7: return "Esix";
        case 8: return "Solaris";
        case 9: return "Irix";
        case 10: return "SCO";
        case 11: return "Dell";
        case 12: return "NCR";
        case 13: return "LynxOS";
        case 14: return "VxWorks";
        case 15: return "psos";
        case 16: return "QNX";
        case 17: return "U-Boot";
        case 18: return "RTEMS";
        case 19: return "OSE";
        case 20: return "Plan 9";
        case 21: return "Inferno";
        case 22: return "Linux Kernel";
        default: return "Unknown";
    }
}

std::string UImageParser::get_arch_name(uint8_t arch) {
    switch (arch) {
        case 0: return "Invalid";
        case 1: return "Alpha";
        case 2: return "ARM";
        case 3: return "AVR32";
        case 4: return "Blackfin";
        case 5: return "x86";
        case 6: return "IA64";
        case 7: return "MIPS";
        case 8: return "NDS32";
        case 9: return "Nios-II";
        case 10: return "PowerPC";
        case 11: return "RISC-V";
        case 12: return "S390";
        case 13: return "SH";
        case 14: return "SPARC";
        case 15: return "x86_64";
        default: return "Unknown";
    }
}

std::string UImageParser::get_image_type(uint8_t type) {
    switch (type) {
        case 1: return "Standalone";
        case 2: return "Kernel";
        case 3: return "RAMDisk";
        case 4: return "Multi";
        case 5: return "Firmware";
        case 6: return "Script";
        case 7: return "Filesystem";
        case 8: return "Flat Device Tree";
        case 9: return "Kernel with FDT";
        default: return "Unknown";
    }
}

std::string UImageParser::get_compression_type(uint8_t comp) {
    switch (comp) {
        case 0: return "None";
        case 1: return "gzip";
        case 2: return "bzip2";
        case 3: return "lzma";
        case 4: return "lz4";
        case 5: return "zstd";
        default: return "Unknown";
    }
}




bool UImageParser::match(const std::vector<uint8_t>& blob, size_t offset) {
    if (offset + 4 > blob.size()) return false;
    uint32_t magic = (blob[offset] << 24) | (blob[offset + 1] << 16) |
                     (blob[offset + 2] << 8) | blob[offset + 3];
    return magic == UIMAGE_MAGIC;
}

ScanResult UImageParser::parse(const std::vector<uint8_t>& blob, size_t offset) {
    ScanResult result;
    result.type="UIMAGE";
    result.extractorType = result.type;
    result.offset = offset;
    if (offset + 64 > blob.size())
    {
        result.length = 0;
        result.info = "Invalid Header";
        return result;
    }


    // Parse header fields using big-endian
uint32_t timestamp   = read_be32(blob, offset + 8);
uint32_t size        = read_be32(blob, offset + 12);
uint32_t loadAddr    = read_be32(blob, offset + 16);
uint32_t entryPoint  = read_be32(blob, offset + 20);
uint32_t dataCrc     = read_be32(blob, offset + 24);
uint8_t osType   = blob[offset + 28];
uint8_t archType = blob[offset + 29];
uint8_t imgType  = blob[offset + 30];
uint8_t compType = blob[offset + 31];

std::string timestampStr = format_timestamp(timestamp);
// Extract image name
std::string imageName;
for (size_t i = 0; i < 32; ++i) {
    char c = static_cast<char>(blob[offset + 32 + i]);
    if (c == '\0') break;
    imageName += c;
}
if (imageName.empty()) imageName = "uimage_payload";
    std::ostringstream info;
    std::time_t ts = timestamp;
    std::string osName   = get_os_name(osType);
std::string archName = get_arch_name(archType);
std::string typeName = get_image_type(imgType);
std::string compName = get_compression_type(compType);

if(compName.compare("Unknown") == 0)
{
    return result;
    
}


    info << "UImage: " + imageName 
         << ", timestamp=" + timestampStr
         << ", OS=" + osName +
               ", CPU=" + archName +
               ", Type=" + typeName +
               ", Compression=" + compName;
    result.info = info.str();
    result.length = size;
    result.isValid = true;
    return result;
}




REGISTER_PARSER(UImageParser)