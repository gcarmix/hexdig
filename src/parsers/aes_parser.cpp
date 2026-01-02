#include "parser_registration.hpp"
#include "aes.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>

static bool cmp16(const std::vector<uint8_t>& blob, size_t off, const uint8_t* sig) {
    return off + 16 <= blob.size() && std::equal(sig, sig + 16, blob.begin() + off);
}
static ScanResult make(size_t offset,
                       const std::string& name,
                       size_t tableBytes,
                       const std::string& extra = "")
{
    ScanResult r;
    r.offset   = offset;
    r.type     = "AES";
    r.length   = tableBytes;
    r.isValid  = true;
    r.confident = true;

    std::ostringstream oss;
    oss << name;
    if (!extra.empty()) {
        oss << ", " << extra;
    }
    oss << ", entries=256, table bytes=" << tableBytes;

    r.info = oss.str();
    return r;
}

class AESParser : public BaseParser {
public:
    std::string name() const override { return "AES"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult dummy;
        return identify(blob, offset, dummy);
    }

    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult r;
        if (!identify(blob, offset, r)) {
            r.offset = offset;
            r.type = "AES";
            r.length = 0;
            r.info = "No AES table recognized";
            r.isValid = false;
        }
        return r;
    }

private:
    static bool identify(const std::vector<uint8_t>& blob, size_t off, ScanResult& out) {
        if (cmp16(blob, off, AES_SBOX))     { out = make(off, "AES S-box", 256); return true; }
        if (cmp16(blob, off, AES_INV_SBOX)) { out = make(off, "AES inverse S-box", 256); return true; }
        if (cmp16(blob, off, AES_RCON))     { out = make(off, "AES Rcon", 256); return true; }

        if (cmp16(blob, off, AES_TE0_LE))   { out = make(off, "AES Te0", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TE0_BE))   { out = make(off, "AES Te0", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TE1_LE))   { out = make(off, "AES Te1", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TE1_BE))   { out = make(off, "AES Te1", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TE2_LE))   { out = make(off, "AES Te2", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TE2_BE))   { out = make(off, "AES Te2", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TE3_LE))   { out = make(off, "AES Te3", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TE3_BE))   { out = make(off, "AES Te3", 1024, "BE"); return true; }

        if (cmp16(blob, off, AES_TD0_LE))   { out = make(off, "AES Td0", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TD0_BE))   { out = make(off, "AES Td0", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TD1_LE))   { out = make(off, "AES Td1", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TD1_BE))   { out = make(off, "AES Td1", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TD2_LE))   { out = make(off, "AES Td2", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TD2_BE))   { out = make(off, "AES Td2", 1024, "BE"); return true; }
        if (cmp16(blob, off, AES_TD3_LE))   { out = make(off, "AES Td3", 1024, "LE"); return true; }
        if (cmp16(blob, off, AES_TD3_BE))   { out = make(off, "AES Td3", 1024, "BE"); return true; }


        return false;
    }
};

REGISTER_PARSER(AESParser)
