#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include "helpers.hpp"
#include "logger.hpp"
#include "dtb.hpp"

namespace fs = std::filesystem;




static std::string format_value(const std::vector<uint8_t>& val) {
    if (val.empty()) return "<empty>";

    // Check if printable string(s)
    bool printable = true;
    for (auto b : val) {
        if (!(b >= 32 && b < 127) && b != 0) { printable = false; break; }
    }
    if (printable) {
        std::string s(reinterpret_cast<const char*>(val.data()), val.size());
        // Handle multiple strings separated by NUL
        std::ostringstream oss;
        size_t start = 0;
        while (start < s.size()) {
            size_t cut = s.find('\0', start);
            if (cut == std::string::npos) cut = s.size();
            std::string part = s.substr(start, cut - start);
            if (!part.empty()) {
                if (oss.tellp() > 0) oss << ", ";
                oss << "\"" << part << "\"";
            }
            start = cut + 1;
        }
        return oss.str();
    }

    // If length is multiple of 4, interpret as cells
    if (val.size() % 4 == 0) {
        std::ostringstream oss;
        oss << "<";
        for (size_t i = 0; i < val.size(); i += 4) {
            uint32_t cell = read_be32(val, i);
            oss << "0x" << std::hex << cell << std::dec;
            if (i + 4 < val.size()) oss << ", ";
        }
        oss << ">";
        return oss.str();
    }

    // Fallback
    return "<" + std::to_string(val.size()) + " bytes>";
}

class DTBExtractor : public BaseExtractor {
public:
std::string name() const override { return "DTB"; };

void extract(const std::vector<uint8_t>& blob,
                           size_t offset,fs::path extractionPath) {

    if (offset + sizeof(FdtHeader) > blob.size()) return;

    FdtHeader h{};
    h.magic            = read_be32(blob, offset + 0);
    h.totalsize        = read_be32(blob, offset + 4);
    h.off_dt_struct    = read_be32(blob, offset + 8);
    h.off_dt_strings   = read_be32(blob, offset + 12);
    h.off_mem_rsvmap   = read_be32(blob, offset + 16);
    h.version          = read_be32(blob, offset + 20);
    h.last_comp_version= read_be32(blob, offset + 24);
    h.boot_cpuid_phys  = read_be32(blob, offset + 28);
    h.size_dt_strings  = read_be32(blob, offset + 32);
    h.size_dt_struct   = read_be32(blob, offset + 36);

    if (h.magic != FDT_MAGIC) {
        Logger::error("DTBExtractor: Invalid magic at offset " + to_hex(offset));
        return;
    }
    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);

    std::ofstream out(extractionPath.string()+"/tree.dts");
    if (!out) {
        Logger::error("DTBExtractor: Cannot open output file");
        return;
    }

    size_t pos = offset + h.off_dt_struct;
    size_t end = pos + h.size_dt_struct;
    int depth = 0;

    auto indent = [&](int d){ return std::string(d * 2, ' '); };

    while (pos + 4 <= blob.size() && pos < end) {
        uint32_t token = read_be32(blob, pos);
        pos += 4;
        switch (token) {
            case FDT_BEGIN_NODE: {
                size_t start = pos;
                while (pos < blob.size() && blob[pos] != 0) pos++;
                std::string name(reinterpret_cast<const char*>(&blob[start]), pos - start);
                pos++;
                pos = (pos + 3) & ~3;
                out << indent(depth) << name << " {\n";
                depth++;
                break;
            }
            case FDT_END_NODE: {
                depth--;
                out << indent(depth) << "};\n";
                break;
            }
            case FDT_PROP: {
                uint32_t len = read_be32(blob, pos); pos += 4;
                uint32_t nameoff = read_be32(blob, pos); pos += 4;
                std::vector<uint8_t> val(blob.begin() + pos, blob.begin() + pos + len);
                pos += len;
                pos = (pos + 3) & ~3;

                size_t str_start = offset + h.off_dt_strings + nameoff;
                std::string pname;
                if (str_start < blob.size()) {
                    const char* p = reinterpret_cast<const char*>(&blob[str_start]);
                    pname = std::string(p);
                }

                out << indent(depth) << pname << " = " << format_value(val) << ";\n";
                break;
            }
            case FDT_NOP:
                break;
            case FDT_END:
                out.close();
                Logger::debug("DTBExtractor: Wrote tree to dtb_output/tree.dts");
                return;
            default:
                Logger::error("DTBExtractor: Unknown token");
                return;
        }
    }
}


};

REGISTER_EXTRACTOR(DTBExtractor)