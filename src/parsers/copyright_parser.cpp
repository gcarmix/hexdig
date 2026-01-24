#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <cctype>

class CopyrightParser : public BaseParser {
public:
    std::string name() const override { return "COPYRIGHT"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        const char* kw = "copyright";
        size_t kwLen = 9;

        if (offset + kwLen > blob.size())
            return false;

        for (size_t i = 0; i < kwLen; i++) {
            if (std::tolower(blob[offset + i]) != kw[i])
                return false;
        }

        return true;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "COPYRIGHT";
        //r.extractorType = "RAW";
        r.isValid = false;
        r.length = 0;

        std::string text;
        text.reserve(128);

        size_t i = offset;

        // Extract until null, newline, or 100 bytes
        while (i < blob.size() && text.size() < 100) {
            uint8_t c = blob[i];

            if (c == 0x00 || c == '\n' || c == '\r')
                break;

            // Only accept printable ASCII
            if (c < 0x20 || c > 0x7E)
                break;

            text.push_back(static_cast<char>(c));
            i++;
        }

        // Require at least "copyright" + something
        if (text.size() > 10) {
            r.isValid = true;
            r.length = text.size();
            r.info = text;
        } else {
            r.isValid = false;
            r.length = text.size();
            r.info = "Short or invalid copyright string";
        }

        return r;
    }
};

REGISTER_PARSER(CopyrightParser);
