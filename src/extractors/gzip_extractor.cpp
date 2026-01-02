#include "base_extractor.hpp"   // contains BaseExtractor
#include "extractor_registration.hpp"
#include <zlib.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <string>
#include "helpers.hpp"
#include "logger.hpp"

namespace fs = std::filesystem;

class GZIPExtractor : public BaseExtractor {
public:
    std::string name() const override { return "GZIP"; }

    void extract(const std::vector<std::uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override
    {
        if (offset >= blob.size()) {
            Logger::error("GZIP Offset beyond blob size");
        }
        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);

        // Prepare zlib stream
        z_stream strm{};
        strm.next_in = const_cast<Bytef*>(blob.data() + offset);
        strm.avail_in = blob.size() - offset;

        // 16+MAX_WBITS tells zlib to expect GZIP header
        if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
            Logger::error("GZIP inflateInit2 failed");
        }

        std::vector<uint8_t> out;
        const size_t CHUNK = 16384;
        std::vector<uint8_t> buffer(CHUNK);

        int ret;
        do {
            strm.next_out = buffer.data();
            strm.avail_out = buffer.size();

            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) {
                inflateEnd(&strm);
                Logger::error("GZIP inflate stream error");
            }

            size_t have = buffer.size() - strm.avail_out;
            out.insert(out.end(), buffer.begin(), buffer.begin() + have);

        } while (ret != Z_STREAM_END);

        inflateEnd(&strm);

        // Write decompressed data to extractionPath

        std::ofstream f(extractionPath/fs::path("decompressed.bin"), std::ios::binary);
        if (!f) {
            Logger::error("GZIP Cannot open output file: " + extractionPath.string());
        }
        f.write(reinterpret_cast<const char*>(out.data()), out.size());
    }
};

REGISTER_EXTRACTOR(GZIPExtractor)