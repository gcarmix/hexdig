#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"
#include "logger.hpp"

class CABParser : public BaseParser {
public:
    std::string name() const override { return "CAB"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        // Signature "MSCF" (4D 53 43 46)
        if (offset + 4 > blob.size()) return false;
        return blob[offset] == 'M' &&
               blob[offset+1] == 'S' &&
               blob[offset+2] == 'C' &&
               blob[offset+3] == 'F';
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "CAB";
        r.extractorType ="7Z";
        r.isValid = false;
        r.length = 0;

        // Cabinet header is at least 36 bytes
        //  0  : signature "MSCF"
        //  4  : reserved (u32)
        //  8  : cbCabinet (u32)
        //  12 : reserved1 (u32)
        //  16 : reserved2 (u32)
        //  20 : coffFiles (u32)
        //  24 : nFolders (u32)
        //  28 : nFiles   (u32)
        //  32 : flags    (u16)
        //  34 : setID    (u16)
        //  36 : iCabinet (u16)  <-- total min header 38 bytes; many docs cite 36 before setID/iCabinet, but layout includes them
        if (offset + 38 > blob.size()) {
            r.info = "Truncated CAB header";
            r.length = blob.size() - offset;
            return r;
        }

        uint32_t cbCabinet = read_le32(blob, offset + 8);
        uint32_t coffFiles = read_le32(blob, offset + 20);
        uint32_t nFolders  = read_le32(blob, offset + 24);
        uint32_t nFiles    = read_le32(blob, offset + 28);
        uint16_t flags     = read_le16(blob, offset + 32);
        uint16_t setID     = read_le16(blob, offset + 34);
        uint16_t iCabinet  = read_le16(blob, offset + 36);

        // Flags of interest:
        // 0x0001: has reserved per-cabinet area (cbCFHeader + abReserved)
        // 0x0004: has prev cabinet in set
        // 0x0008: has next cabinet in set
        bool hasReserved = (flags & 0x0001) != 0;
        bool hasPrev     = (flags & 0x0004) != 0;
        bool hasNext     = (flags & 0x0008) != 0;

        // Basic plausibility checks
        size_t available = blob.size() - offset;
        bool sizeFits = (cbCabinet > 0 && cbCabinet <= available);
        bool countsPlausible = (nFolders <= 0x100000) && (nFiles <= 0x100000);

        // The files table offset should be within the cabinet
        bool filesOffPlausible = (coffFiles == 0) || (coffFiles >= 38 && coffFiles < cbCabinet);

        r.length = std::min<size_t>(cbCabinet, available);
        r.isValid = sizeFits && filesOffPlausible && countsPlausible;
        std::ostringstream info;
        info << "Microsoft Cabinet archive, size=" << cbCabinet
             << " bytes, folders=" << nFolders
             << ", files=" << nFiles
             << ", flags=" << describeFlags(flags)
             << ", setID=" << setID
             << ", index=" << iCabinet
             << ", coffFiles=" << coffFiles;
        r.info = info.str();
        Logger::debug(r.info);

        return r;
    }

private:
    std::string describeFlags(uint16_t flags) {
        std::ostringstream os;
        bool first = true;
        auto add = [&](const char* s){
            if (!first) os << "|";
            os << s;
            first = false;
        };
        if (flags & 0x0001) add("RESERVED");
        if (flags & 0x0002) add("CHKTREE");   // rarely used; placeholder
        if (flags & 0x0004) add("PREV");
        if (flags & 0x0008) add("NEXT");
        if (flags == 0 || first) add("NONE");
        return os.str();
    }
};

REGISTER_PARSER(CABParser)
