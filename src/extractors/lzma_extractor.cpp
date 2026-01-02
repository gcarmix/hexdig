#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "helpers.hpp"
#include <lzma.h>  // Requires liblzma (xz-utils)

namespace fs = std::filesystem;

class LZMAExtractor : public BaseExtractor {
public:
    std::string name() const override { return "LZMA"; }

    void extract(const std::vector<std::uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override {
        if (offset + 13 > blob.size()) {
            std::cerr << "[LZMAExtractor] Invalid header at offset " << offset << "\n";
            return;
        }

        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);

        const uint8_t* comp = &blob[offset];
        size_t comp_len = blob.size() - offset;

        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_alone_decoder(&strm, UINT64_MAX);
        if (ret != LZMA_OK) {
            std::cerr << "[LZMAExtractor] Failed to init decoder\n";
            return;
        }

        strm.next_in = comp;
        strm.avail_in = comp_len;

        std::vector<uint8_t> out;
        std::vector<uint8_t> buf(1 << 16); // 64 KiB buffer

        while (true) {
            strm.next_out = buf.data();
            strm.avail_out = buf.size();

            ret = lzma_code(&strm, LZMA_FINISH);
            if (ret != LZMA_OK && ret != LZMA_STREAM_END && ret != LZMA_BUF_ERROR) {
                std::cerr << "[LZMAExtractor] Decompression error\n";
                lzma_end(&strm);
                return;
            }

            size_t produced = buf.size() - strm.avail_out;
            out.insert(out.end(), buf.data(), buf.data() + produced);

            if (ret == LZMA_STREAM_END) break;
            if (ret == LZMA_BUF_ERROR && strm.avail_in == 0) break;
        }

        lzma_end(&strm);

        // Write output to file
        fs::path outFile = extractionPath / "lzma_extracted.bin";
        std::ofstream ofs(outFile, std::ios::binary);
        if (!ofs) {
            std::cerr << "[LZMAExtractor] Failed to open output file\n";
            return;
        }
        ofs.write(reinterpret_cast<const char*>(out.data()), out.size());
        ofs.close();

        std::cout << "[LZMAExtractor] Wrote " << out.size()
                  << " bytes to " << outFile << "\n";
    }
};
REGISTER_EXTRACTOR(LZMAExtractor)