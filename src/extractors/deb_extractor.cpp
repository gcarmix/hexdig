#include "base_extractor.hpp"
#include "extractor_registration.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "helpers.hpp"
#include "logger.hpp"

#ifndef _WIN32
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;

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

std::string sanitizeMemberName(std::string name) {
    name = trim(name);
    if (!name.empty() && name.back() == '/') {
        name.pop_back();
    }
    if (name.empty()) {
        return "member.bin";
    }
    for (char& c : name) {
        if (c == '/' || c == '\\') {
            c = '_';
        }
    }
    return name;
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

bool extractArMembers(const std::vector<uint8_t>& blob, size_t offset, const fs::path& outDir) {
    static constexpr char kDebMagic[] = "!<arch>\n";
    if (offset + 8 > blob.size() ||
        std::memcmp(&blob[offset], kDebMagic, sizeof(kDebMagic) - 1) != 0) {
        return false;
    }

    size_t pos = offset + 8;
    bool wroteAny = false;
    while (pos + kArHeaderSize <= blob.size()) {
        if (!(blob[pos + 58] == '`' && blob[pos + 59] == '\n')) {
            break;
        }

        size_t memberSize = 0;
        if (!parseDecimal(blob, pos, memberSize)) {
            break;
        }

        std::string memberName(
            reinterpret_cast<const char*>(&blob[pos + kArNameOffset]),
            kArNameLen
        );
        memberName = sanitizeMemberName(memberName);

        const size_t dataStart = pos + kArHeaderSize;
        if (dataStart + memberSize > blob.size()) {
            break;
        }

        fs::path outFile = outDir / memberName;
        std::ofstream out(outFile, std::ios::binary);
        if (!out) {
            return wroteAny;
        }
        out.write(reinterpret_cast<const char*>(&blob[dataStart]), static_cast<std::streamsize>(memberSize));
        wroteAny = true;

        pos = dataStart + memberSize + (memberSize & 1U);
    }
    return wroteAny;
}

int runCommand(const std::string& cmd) {
#ifdef _WIN32
    return std::system(cmd.c_str());
#else
    const int rc = std::system(cmd.c_str());
    if (rc == -1) {
        return rc;
    }
    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }
    return rc;
#endif
}

}  // namespace

class DebExtractor : public BaseExtractor {
public:
    std::string name() const override { return "DEB"; }

    void extract(const std::vector<uint8_t>& blob, size_t offset, fs::path extractionPath) override {
        extractionPath = extractionPath / fs::path(to_hex(static_cast<int>(offset)));
        fs::create_directories(extractionPath);

        if (offset >= blob.size()) {
            return;
        }

        fs::path tempDebPath = extractionPath / "package.deb";
        {
            std::ofstream out(tempDebPath, std::ios::binary);
            if (!out) {
                Logger::error("DebExtractor: cannot create temporary package file");
                return;
            }
            out.write(reinterpret_cast<const char*>(&blob[offset]),
                      static_cast<std::streamsize>(blob.size() - offset));
        }

        std::ostringstream cmd;
        cmd << "7z x \"" << tempDebPath.string() << "\" -o\"" << extractionPath.string()
            << "\" -y -p\"\"";
#ifndef _WIN32
        cmd << " > /dev/null 2>&1";
#endif

        const int sevenZipResult = runCommand(cmd.str());
        if (sevenZipResult == 0) {
            fs::remove(tempDebPath);
            return;
        }

        Logger::debug("DebExtractor: 7z failed, using internal ar fallback");
        const bool fallbackOk = extractArMembers(blob, offset, extractionPath);
        if (!fallbackOk) {
            Logger::error("DebExtractor: extraction failed with both 7z and fallback");
        }
        fs::remove(tempDebPath);
    }
};

REGISTER_EXTRACTOR(DebExtractor)
