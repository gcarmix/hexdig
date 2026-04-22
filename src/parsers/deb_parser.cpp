#include "base_parser.hpp"
#include "parser_registration.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr size_t kArHeaderSize = 60;
constexpr size_t kArNameOffset = 0;
constexpr size_t kArNameLen = 16;
constexpr size_t kArSizeOffset = 48;
constexpr size_t kArSizeLen = 10;

std::string trim(const std::string& in) {
    size_t start = 0;
    while (start < in.size() && std::isspace(static_cast<unsigned char>(in[start]))) {
        ++start;
    }
    size_t end = in.size();
    while (end > start && std::isspace(static_cast<unsigned char>(in[end - 1]))) {
        --end;
    }
    return in.substr(start, end - start);
}

std::string normalizeArName(const std::vector<uint8_t>& blob, size_t headerOffset) {
    std::string raw(reinterpret_cast<const char*>(&blob[headerOffset + kArNameOffset]), kArNameLen);
    raw = trim(raw);
    if (!raw.empty() && raw.back() == '/') {
        raw.pop_back();
    }
    return raw;
}

bool parseDecimal(const std::vector<uint8_t>& blob, size_t headerOffset, size_t& outSize) {
    std::string raw(reinterpret_cast<const char*>(&blob[headerOffset + kArSizeOffset]), kArSizeLen);
    raw = trim(raw);
    if (raw.empty()) return false;
    if (!std::all_of(raw.begin(), raw.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return false;
    }
    try {
        outSize = static_cast<size_t>(std::stoull(raw));
    } catch (...) {
        return false;
    }
    return true;
}

bool hasArTerminator(const std::vector<uint8_t>& blob, size_t headerOffset) {
    return blob[headerOffset + 58] == '`' && blob[headerOffset + 59] == '\n';
}

}  // namespace

class DebParser : public BaseParser {
public:
    std::string name() const override { return "DEB"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        static constexpr char kDebMagic[] = "!<arch>\n";
        return offset + 8 <= blob.size() &&
               std::memcmp(&blob[offset], kDebMagic, sizeof(kDebMagic) - 1) == 0;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult result;
        result.offset = offset;
        result.type = "DEB";
        result.extractorType = "DEB";
        result.length = 0;
        result.isValid = false;
        result.confident = false;

        if (!match(blob, offset)) {
            result.info = "Missing ar magic";
            return result;
        }

        size_t pos = offset + 8;
        size_t members = 0;
        bool hasDebianBinary = false;
        bool hasControl = false;
        bool hasData = false;
        std::string controlMember;
        std::string dataMember;

        while (pos + kArHeaderSize <= blob.size()) {
            if (!hasArTerminator(blob, pos)) {
                break;
            }

            size_t memberSize = 0;
            if (!parseDecimal(blob, pos, memberSize)) {
                break;
            }

            const std::string memberName = normalizeArName(blob, pos);
            const size_t dataStart = pos + kArHeaderSize;
            if (dataStart + memberSize > blob.size()) {
                break;
            }

            if (memberName == "debian-binary") {
                hasDebianBinary = true;
                std::string version(reinterpret_cast<const char*>(&blob[dataStart]),
                                    std::min<size_t>(memberSize, 4));
                if (version.rfind("2.0", 0) != 0) {
                    hasDebianBinary = false;
                }
            } else if (memberName.rfind("control.tar", 0) == 0) {
                hasControl = true;
                controlMember = memberName;
            } else if (memberName.rfind("data.tar", 0) == 0) {
                hasData = true;
                dataMember = memberName;
            }

            ++members;
            pos = dataStart + memberSize + (memberSize & 1U);
        }

        result.length = (pos > offset) ? (pos - offset) : 0;
        result.isValid = hasDebianBinary && hasControl && hasData;
        result.confident = result.isValid;

        std::ostringstream info;
        info << "Debian package (.deb), members=" << members;
        if (!controlMember.empty()) {
            info << ", control=" << controlMember;
        }
        if (!dataMember.empty()) {
            info << ", data=" << dataMember;
        }
        if (!result.isValid) {
            info << ", invalid deb layout";
        }
        result.info = info.str();

        return result;
    }
};

REGISTER_PARSER(DebParser)
