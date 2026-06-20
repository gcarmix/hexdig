#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <lzo/lzo1x.h>
#include "helpers.hpp"
#include "logger.hpp"
#include "lzop.hpp"

namespace fs = std::filesystem;

// Decompresses an lzop (.lzo) stream natively using liblzo2. The parser of the
// same name ("LZO") identifies the stream and selects this extractor.
class LZOExtractor : public BaseExtractor {
public:
    std::string name() const override { return "LZO"; }

    void extract(const std::vector<std::uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override {
        if (offset >= blob.size()) {
            Logger::error("LZO Offset beyond blob size");
            return;
        }

        LzopHeader h;
        if (!parse_lzop_header(blob, offset, h)) {
            Logger::error("LZO Invalid lzop header");
            return;
        }

        // Initialize liblzo2 once per process.
        static bool lzoInit = false;
        if (!lzoInit) {
            if (lzo_init() != LZO_E_OK) {
                Logger::error("LZO lzo_init failed");
                return;
            }
            lzoInit = true;
        }

        std::vector<uint8_t> out;
        size_t p = h.blockStart;

        for (;;) {
            uint32_t dstLen = 0;
            if (!lzop_rd32(blob, p, dstLen)) {
                Logger::error("LZO Truncated block size");
                break;
            }
            if (dstLen == 0) break; // end-of-stream marker

            uint32_t srcLen = 0;
            if (!lzop_rd32(blob, p, srcLen)) {
                Logger::error("LZO Truncated compressed size");
                break;
            }
            if (srcLen == 0 || srcLen > dstLen) {
                Logger::error("LZO Invalid block sizes");
                break;
            }

            // Skip per-block checksums (uncompressed, then compressed).
            if (h.flags & LZOP_F_ADLER32_D) p += 4;
            if (h.flags & LZOP_F_CRC32_D)   p += 4;
            if (srcLen < dstLen) {
                if (h.flags & LZOP_F_ADLER32_C) p += 4;
                if (h.flags & LZOP_F_CRC32_C)   p += 4;
            }

            if (p + srcLen > blob.size()) {
                Logger::error("LZO Compressed block exceeds data");
                break;
            }

            if (out.size() + dstLen > MAX_ANALYZED_FILE_SIZE) {
                Logger::error("LZO Decompressed data too large");
                return;
            }

            size_t outBase = out.size();
            out.resize(outBase + dstLen);

            if (srcLen < dstLen) {
                lzo_uint decLen = dstLen;
                int ret = lzo1x_decompress_safe(&blob[p], srcLen,
                                                &out[outBase], &decLen, nullptr);
                if (ret != LZO_E_OK || decLen != dstLen) {
                    Logger::error("LZO Block decompression failed");
                    return;
                }
            } else {
                // Stored (incompressible) block: copy verbatim.
                std::copy(blob.begin() + p, blob.begin() + p + srcLen,
                          out.begin() + outBase);
            }

            p += srcLen;
        }

        extractionPath = extractionPath / fs::path(to_hex(offset));
        fs::create_directories(extractionPath);

        // Prefer the original file name recorded in the header when present.
        std::string outName = "decompressed.bin";
        if (!h.name.empty()) {
            fs::path candidate(h.name);
            if (!candidate.filename().empty())
                outName = candidate.filename().string();
        }

        std::ofstream f(extractionPath / fs::path(outName), std::ios::binary);
        if (!f) {
            Logger::error("LZO Cannot open output file: " + extractionPath.string());
            return;
        }
        f.write(reinterpret_cast<const char*>(out.data()), out.size());
    }
};

REGISTER_EXTRACTOR(LZOExtractor)
