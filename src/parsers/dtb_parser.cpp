#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <iostream>
#include "helpers.hpp"
#include <stdexcept>
#include "dtb.hpp"
#include <vector>
#include <string>
#include <map>
#include <memory>


class DTBParser : public BaseParser {
public:
    std::string name() const override { return "DTB"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override;
    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset ) override;
};


bool DTBParser::match(const std::vector<std::uint8_t>& blob, size_t offset) {
    if (offset + sizeof(FdtHeader) > blob.size()) return false;
    uint32_t magic = read_be32(blob,offset);
    return magic == FDT_MAGIC;
}

ScanResult DTBParser::parse(const std::vector<std::uint8_t>& blob, size_t offset) {
    ScanResult root;
    root.offset = offset;
    root.type = "DTB";
    root.extractorType = root.type;
    root.length = 0;
    root.info = "Device Tree Blob";
    root.source = "";
    root.isValid = true;

    if (!match(blob, offset)) {
        root.isValid = false;
        root.info = "Invalid DTB magic";
        return root;
    }

    // Parse header
    FdtHeader h{};
    h.magic            = read_be32(blob,offset+0);
    h.totalsize        = read_be32(blob,offset+4);
    h.off_dt_struct    = read_be32(blob,offset+8);
    h.off_dt_strings   = read_be32(blob,offset+12);
    h.off_mem_rsvmap   = read_be32(blob,offset+16);
    h.version          = read_be32(blob,offset+20);
    h.last_comp_version= read_be32(blob,offset+24);
    h.boot_cpuid_phys  = read_be32(blob,offset+28);
    h.size_dt_strings  = read_be32(blob,offset+32);
    h.size_dt_struct   = read_be32(blob,offset+36);

    // Header fields are read from the file. With only a 4-byte magic the
    // match is prone to false positives in unrelated binaries; clamp every
    // subsequent read to blob.size() and reject obviously bogus headers.
    size_t remaining = blob.size() - offset;
    if (h.totalsize < sizeof(FdtHeader) || h.totalsize > remaining ||
        h.off_dt_struct  > h.totalsize ||
        h.off_dt_strings > h.totalsize ||
        (size_t)h.off_dt_struct  + (size_t)h.size_dt_struct  > (size_t)h.totalsize ||
        (size_t)h.off_dt_strings + (size_t)h.size_dt_strings > (size_t)h.totalsize) {
        root.length = std::min<size_t>(h.totalsize, remaining);
        root.isValid = false;
        root.info = "Implausible DTB header (likely false positive)";
        return root;
    }
    root.length = h.totalsize;

    const size_t imageEnd = offset + (size_t)h.totalsize;  // already clamped to blob.size() above
    size_t pos = offset + h.off_dt_struct;
    size_t end = std::min<size_t>(pos + h.size_dt_struct, imageEnd);

    while (pos + 4 <= blob.size() && pos < end) {
        uint32_t token = read_be32(blob,pos); pos += 4;
        switch (token) {
            case FDT_BEGIN_NODE: {
                size_t start = pos;
                while (pos < blob.size() && blob[pos] != 0) pos++;
                std::string name(reinterpret_cast<const char*>(&blob[start]), pos - start);
                pos++;
                pos = (pos + 3) & ~3;

                /*ScanResult node;
                node.offset = start;
                node.type = "Node";
                node.length = 0;
                node.info = name;
                node.isValid = true;

                stack.back()->children.push_back(node);
                stack.push_back(&stack.back()->children.back());*/
                break;
            }
            case FDT_END_NODE: {
                //stack.pop_back();
                break;
            }
            case FDT_PROP: {
                if (pos + 8 > end) { root.isValid = false; root.info = "Truncated FDT_PROP header"; return root; }
                uint32_t len = read_be32(blob,pos); pos += 4;
                uint32_t nameoff = read_be32(blob,pos); pos += 4;
                if ((size_t)len > end - pos) { root.isValid = false; root.info = "FDT_PROP length out of bounds"; return root; }
                std::vector<uint8_t> val(blob.begin() + pos, blob.begin() + pos + len);
                pos += len;
                pos = (pos + 3) & ~3;

                // Property name: nameoff is an offset into the strings block.
                // Bound both the start and the strnlen-style read against the
                // strings region so a bogus nameoff can't run past EOF.
                std::string pname;
                size_t str_block = offset + h.off_dt_strings;
                size_t str_block_end = str_block + h.size_dt_strings;
                if ((size_t)nameoff < h.size_dt_strings) {
                    size_t s = str_block + nameoff;
                    size_t e = s;
                    while (e < str_block_end && blob[e] != 0) e++;
                    pname.assign(reinterpret_cast<const char*>(&blob[s]), e - s);
                }

                /*ScanResult prop;
                prop.offset = pos;
                prop.type = "Property";
                prop.length = len;
                prop.info = pname;
                prop.isValid = true;

                stack.back()->children.push_back(prop);*/
                break;
            }
            case FDT_NOP:
                break;
            case FDT_END:
                return root;
            default:
                root.isValid = false;
                root.info = "Unknown token in DTB structure";
                return root;
        }
    }

    root.isValid = false;
    root.info = "DTB structure incomplete";
    return root;
}

REGISTER_PARSER(DTBParser)