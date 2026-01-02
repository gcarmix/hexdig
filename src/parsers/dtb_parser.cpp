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

    root.length = h.totalsize;

    size_t pos = offset + h.off_dt_struct;
    size_t end = pos + h.size_dt_struct;
    //std::vector<ScanResult*> stack;
    //stack.push_back(&root);

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
                uint32_t len = read_be32(blob,pos); pos += 4;
                uint32_t nameoff = read_be32(blob,pos); pos += 4;
                std::vector<uint8_t> val(blob.begin() + pos, blob.begin() + pos + len);
                pos += len;
                pos = (pos + 3) & ~3;

                size_t str_start = offset + h.off_dt_strings + nameoff;
                std::string pname;
                if (str_start < blob.size()) {
                    const char* p = reinterpret_cast<const char*>(&blob[str_start]);
                    pname = std::string(p);
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