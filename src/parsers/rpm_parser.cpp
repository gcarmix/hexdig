#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include "helpers.hpp"

// Parser for an RPM (RPM Package Manager) package.
//
// Layout:
//   0x00  Lead (96 bytes)
//           0x00  magic       0xED 0xAB 0xEE 0xDB
//           0x04  major, minor version (1 byte each)
//           0x06  type        uint16 BE (0=binary, 1=source)
//           0x08  archnum     uint16 BE
//           0x0A  name        66 bytes, NUL-padded
//           0x4C  osnum       uint16 BE
//           0x4E  sig type    uint16 BE (5 = header-style signature)
//           0x50  reserved    16 bytes
//   0x60  Signature header   (rpm header structure, magic 0x8E 0xAD 0xE8 0x01)
//   ....  Main header        (rpm header structure)
//   ....  Payload            (compressed cpio archive, runs to EOF)
//
// The payload length is not stored, so the package is treated as running to the
// end of the data. Extraction is delegated to 7-Zip's RPM handler.
class RPMParser : public BaseParser {
    static constexpr size_t LEAD_SIZE = 96;

public:
    std::string name() const override { return "RPM"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override {
        if (offset + 4 > blob.size()) return false;
        return blob[offset + 0] == 0xED && blob[offset + 1] == 0xAB &&
               blob[offset + 2] == 0xEE && blob[offset + 3] == 0xDB;
    }

    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "RPM";
        r.extractorType = "7Z";   // handed off to the existing 7-Zip extractor
        r.isValid = false;
        r.length = blob.size() - offset; // payload runs to the end of the data

        if (offset + LEAD_SIZE > blob.size()) {
            r.info = "Truncated RPM lead";
            return r;
        }

        uint8_t  major = blob[offset + 4];
        uint8_t  minor = blob[offset + 5];
        uint16_t type  = read_be16(blob, offset + 6);
        std::string pkgName = read_string(blob, offset + 0x0A, 66);

        // Strong confirmation: the signature header immediately follows the lead
        // and starts with the rpm header magic 0x8E 0xAD 0xE8 0x01.
        bool headerOk =
            offset + LEAD_SIZE + 4 <= blob.size() &&
            blob[offset + LEAD_SIZE + 0] == 0x8E &&
            blob[offset + LEAD_SIZE + 1] == 0xAD &&
            blob[offset + LEAD_SIZE + 2] == 0xE8 &&
            blob[offset + LEAD_SIZE + 3] == 0x01;

        std::ostringstream info;
        info << "RPM v" << (int)major << "." << (int)minor << " "
             << (type == 1 ? "source" : "binary") << " package";
        if (!pkgName.empty()) info << ", name=\"" << pkgName << "\"";
        if (!headerOk) info << " (missing header signature)";

        r.info = info.str();
        r.isValid = headerOk;
        return r;
    }
};

REGISTER_PARSER(RPMParser)
