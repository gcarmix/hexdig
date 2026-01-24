#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <cctype>
#include <sstream>
#include "logger.hpp"

class SVGParser : public BaseParser {
public:
    std::string name() const override { return "SVG"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset >= blob.size()) return false;

        // Skip leading whitespace
        size_t i = offset;
        while (i < blob.size() && std::isspace(static_cast<unsigned char>(blob[i])))
            ++i;

        // Optional XML declaration
        if (i + 5 < blob.size() &&
            blob[i] == '<' && blob[i+1] == '?' &&
            (blob[i+2] == 'x' || blob[i+2] == 'X') &&
            (blob[i+3] == 'm' || blob[i+3] == 'M') &&
            (blob[i+4] == 'l' || blob[i+4] == 'L')) {

            // Skip until end of declaration
            size_t declEnd = i;
            while (declEnd + 1 < blob.size() &&
                   !(blob[declEnd] == '?' && blob[declEnd+1] == '>'))
                ++declEnd;
            if (declEnd + 2 >= blob.size()) return false;
            i = declEnd + 2;
            while (i < blob.size() && std::isspace(static_cast<unsigned char>(blob[i])))
                ++i;
        }

        // Now expect <svg ...>
        if (i + 4 >= blob.size()) return false;
        if (blob[i] != '<') return false;

        auto ci = [](uint8_t c){ return static_cast<char>(std::tolower(c)); };

        if (ci(blob[i+1]) != 's' || ci(blob[i+2]) != 'v' || ci(blob[i+3]) != 'g')
            return false;

        // Next char must be space, '>', '/', or newline etc.
        uint8_t next = blob[i+4];
        if (!(std::isspace(next) || next == '>' || next == '/'))
            return false;

        return true;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "SVG";
        r.extractorType = "RAW"; // or whatever raw extractor you use
        r.isValid = false;
        r.length = 0;

        // Find start of <svg
        size_t start = offset;
        while (start < blob.size() && std::isspace(static_cast<unsigned char>(blob[start])))
            ++start;

        // Optionally skip XML declaration again (same as in match)
        if (start + 5 < blob.size() &&
            blob[start] == '<' && blob[start+1] == '?' &&
            (blob[start+2] == 'x' || blob[start+2] == 'X') &&
            (blob[start+3] == 'm' || blob[start+3] == 'M') &&
            (blob[start+4] == 'l' || blob[start+4] == 'L')) {

            size_t declEnd = start;
            while (declEnd + 1 < blob.size() &&
                   !(blob[declEnd] == '?' && blob[declEnd+1] == '>'))
                ++declEnd;
            if (declEnd + 2 >= blob.size()) {
                r.info = "Truncated XML declaration";
                r.length = blob.size() - offset;
                Logger::error("Truncated XML declaration");
                return r;
            }
            start = declEnd + 2;
            while (start < blob.size() && std::isspace(static_cast<unsigned char>(blob[start])))
                ++start;
        }

        // Find closing </svg>
        const std::string endTag = "</svg";
        size_t pos = start;
        size_t endPos = blob.size();

        while (pos < blob.size()) {
            // naive search
            if (pos + endTag.size() > blob.size()) break;

            bool match = true;
            for (size_t j = 0; j < endTag.size(); ++j) {
                if (std::tolower(static_cast<unsigned char>(blob[pos + j])) != endTag[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                Logger::debug("Matched!");
                // advance to '>' of </svg...>
                size_t k = pos + endTag.size();
                while (k < blob.size() && blob[k] != '>')
                    ++k;
                if (k < blob.size()) {
                    endPos = k;
                    break;
                }
            }
            ++pos;
        }

        if (endPos == blob.size()) {
            // No closing tag found; treat as truncated SVG
            r.info = "Truncated SVG (no closing </svg>)";
            r.length = blob.size() - offset;
            r.isValid = false;
            Logger::error("Truncated SVG");
        } else {
            r.length = endPos - offset;
            r.isValid = true;
            r.info = "SVG image";
        }

        return r;
    }
};

REGISTER_PARSER(SVGParser);
