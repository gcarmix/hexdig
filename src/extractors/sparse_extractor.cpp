#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include "helpers.hpp"
#include "logger.hpp"

#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace fs = std::filesystem;

// Android sparse image extractor — expands a sequence of chunks into the
// original raw image. See the parser for the on-disk layout.

static constexpr uint32_t SPARSE_MAGIC      = 0xed26ff3a;
static constexpr uint16_t SPARSE_CHUNK_RAW  = 0xCAC1;
static constexpr uint16_t SPARSE_CHUNK_FILL = 0xCAC2;
static constexpr uint16_t SPARSE_CHUNK_DC   = 0xCAC3;
static constexpr uint16_t SPARSE_CHUNK_CRC  = 0xCAC4;

class SparseExtractor : public BaseExtractor {
public:
    std::string name() const override { return "SPARSE"; }

    void extract(const std::vector<uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override
    {
        if (offset + 28 > blob.size()) {
            Logger::error("SPARSE: offset beyond blob size");
            return;
        }
        if (read_le32(blob, offset) != SPARSE_MAGIC) {
            Logger::error("SPARSE: magic mismatch at offset");
            return;
        }

        uint16_t file_hdr_sz  = read_le16(blob, offset + 8);
        uint16_t chunk_hdr_sz = read_le16(blob, offset + 10);
        uint32_t blk_sz       = read_le32(blob, offset + 12);
        uint32_t total_blks   = read_le32(blob, offset + 16);
        uint32_t total_chunks = read_le32(blob, offset + 20);

        if (file_hdr_sz < 28 || chunk_hdr_sz < 12 ||
            blk_sz < 4 || (blk_sz % 4) != 0) {
            Logger::error("SPARSE: invalid header fields");
            return;
        }

        fs::create_directories(extractionPath);
        extractionPath /= fs::path(to_hex(offset));
        fs::create_directories(extractionPath);

        fs::path outPath = extractionPath / "image.img";
        std::ofstream out(outPath, std::ios::binary);
        if (!out) {
            Logger::error("SPARSE: cannot write " + outPath.string());
            return;
        }

        // Write large filler regions in chunks to cap memory use.
        constexpr size_t BUCKET = 64 * 1024;
        std::vector<char> zero_buf(BUCKET, 0);
        std::vector<char> fill_buf(BUCKET);

        size_t pos = offset + file_hdr_sz;
        uint64_t outBlocks = 0;

        for (uint32_t i = 0; i < total_chunks; i++) {
            if (pos + chunk_hdr_sz > blob.size()) {
                Logger::error("SPARSE: truncated at chunk " + std::to_string(i));
                break;
            }
            uint16_t ct       = read_le16(blob, pos + 0);
            uint32_t chunk_sz = read_le32(blob, pos + 4);
            uint32_t total_sz = read_le32(blob, pos + 8);

            if (total_sz < chunk_hdr_sz || pos + total_sz > blob.size()) {
                Logger::error("SPARSE: malformed chunk " + std::to_string(i));
                break;
            }

            uint64_t bytes_out  = (uint64_t)chunk_sz * blk_sz;
            size_t   payload    = pos + chunk_hdr_sz;
            uint32_t payload_sz = total_sz - chunk_hdr_sz;

            switch (ct) {
                case SPARSE_CHUNK_RAW: {
                    size_t n = std::min<size_t>(payload_sz, (size_t)bytes_out);
                    out.write(reinterpret_cast<const char*>(&blob[payload]), n);
                    break;
                }
                case SPARSE_CHUNK_FILL: {
                    if (payload_sz < 4) {
                        Logger::error("SPARSE: FILL chunk too small");
                        break;
                    }
                    uint32_t fill = read_le32(blob, payload);
                    for (size_t k = 0; k + 4 <= BUCKET; k += 4) {
                        std::memcpy(&fill_buf[k], &fill, 4);
                    }
                    uint64_t remaining = bytes_out;
                    while (remaining) {
                        size_t n = (remaining > BUCKET) ? BUCKET : (size_t)remaining;
                        out.write(fill_buf.data(), n);
                        remaining -= n;
                    }
                    break;
                }
                case SPARSE_CHUNK_DC: {
                    // Materialize holes as zeros so the output matches the
                    // unsparsified image byte-for-byte.
                    uint64_t remaining = bytes_out;
                    while (remaining) {
                        size_t n = (remaining > BUCKET) ? BUCKET : (size_t)remaining;
                        out.write(zero_buf.data(), n);
                        remaining -= n;
                    }
                    break;
                }
                case SPARSE_CHUNK_CRC:
                    // Validation data only — no output bytes.
                    break;
                default:
                    Logger::error("SPARSE: unknown chunk type 0x" +
                                  to_hex((int)ct));
                    break;
            }

            outBlocks += chunk_sz;
            pos += total_sz;
        }

        out.close();

        Logger::debug("SPARSE: wrote " + outPath.string() +
                      " (" + std::to_string(outBlocks * (uint64_t)blk_sz) +
                      " bytes, " + std::to_string(outBlocks) + " blocks)");
        if (outBlocks != total_blks) {
            Logger::debug("SPARSE: block count mismatch: produced " +
                          std::to_string(outBlocks) + " vs header " +
                          std::to_string(total_blks));
        }
    }
};

REGISTER_EXTRACTOR(SparseExtractor)
