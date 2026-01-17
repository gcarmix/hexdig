#include "parser_registration.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <zlib.h>

constexpr uint8_t GZIP_ID1 = 0x1F;
constexpr uint8_t GZIP_ID2 = 0x8B;
constexpr uint8_t GZIP_CM_DEFLATE = 0x08;

class GzipParser : public BaseParser {
public:
    std::string name() const override { return "GZIP"; }

    bool match(const std::vector<std::uint8_t>& blob, size_t offset) override {
        if (offset + 2 > blob.size()) return false;
        return blob[offset] == GZIP_ID1 && blob[offset + 1] == GZIP_ID2 && blob[offset + 2] ==GZIP_CM_DEFLATE;
    }

    ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "GZIP";
        r.extractorType = "GZIP";
        r.isValid = false;

        if (offset + 10 > blob.size()) {
            r.length = 0;
            r.info = "Truncated GZIP header";
            return r;
        }

        uint8_t cm   = blob[offset + 2];
        uint8_t flg  = blob[offset + 3];
        uint32_t mtime = blob[offset + 4] |
                         (blob[offset + 5] << 8) |
                         (blob[offset + 6] << 16) |
                         (blob[offset + 7] << 24);
        uint8_t xfl  = blob[offset + 8];
        uint8_t os   = blob[offset + 9];

        std::ostringstream info;
        info << "GZIP stream, compression method=" << (int)cm
             << ", flags=0x" << std::hex << (int)flg << std::dec
             << ", mtime=" << mtime
             << ", extra flags=" << (int)xfl
             << ", OS=" << (int)os;

        size_t cursor = offset + 10;

        // Optional fields
        if (flg & 0x04) { // FEXTRA
            if (cursor + 2 <= blob.size()) {
                uint16_t xlen = blob[cursor] | (blob[cursor+1] << 8);
                cursor += 2 + xlen;
                info << ", extra field length=" << xlen;
            }
        }
        if (flg & 0x08) { // FNAME
            std::string fname;
            while (cursor < blob.size() && blob[cursor] != 0) {
                fname.push_back((char)blob[cursor++]);
            }
            cursor++;
            if (!fname.empty()) info << ", original filename=\"" << fname << "\"";
        }
        if (flg & 0x10) { // FCOMMENT
            std::string comment;
            while (cursor < blob.size() && blob[cursor] != 0) {
                comment.push_back((char)blob[cursor++]);
            }
            cursor++;
            if (!comment.empty()) info << ", comment=\"" << comment << "\"";
        }
        if (flg & 0x02) { // FHCRC
            cursor += 2; // skip header CRC16
        }

        // Validate trailer
        if (blob.size() < offset + 18) {
            r.length = blob.size() - offset;
            r.info = "Invalid GZIP: too short";
            return r;
        }

        size_t trailerPos = blob.size() - 8;
        uint32_t crc32Trailer = blob[trailerPos] |
                                (blob[trailerPos+1] << 8) |
                                (blob[trailerPos+2] << 16) |
                                (blob[trailerPos+3] << 24);
        uint32_t isizeTrailer = blob[trailerPos+4] |
                                (blob[trailerPos+5] << 8) |
                                (blob[trailerPos+6] << 16) |
                                (blob[trailerPos+7] << 24);

        info << ", trailer CRC32=0x" << std::hex << crc32Trailer
             << ", ISIZE=" << std::dec << isizeTrailer;

        // Recompute CRC32 and ISIZE by decompressing
        z_stream strm{};
        strm.next_in = const_cast<Bytef*>(blob.data() + offset);
        strm.avail_in = blob.size() - offset;

        if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
            r.length = blob.size() - offset;
            r.info = "Invalid GZIP: inflateInit2 failed";
            return r;
        }

        uint32_t crc32Calc = crc32(0L, Z_NULL, 0);
        uint32_t isizeCalc = 0;

        const size_t CHUNK = 16384;
        std::vector<uint8_t> buffer(CHUNK);

        int ret;
        do {
            strm.next_out = buffer.data();
            strm.avail_out = buffer.size();

            ret = inflate(&strm, Z_NO_FLUSH);

            if (ret == Z_STREAM_ERROR) {
                inflateEnd(&strm);
                r.info = "Invalid GZIP: Z_STREAM_ERROR";
                r.length = blob.size() - offset;
                return r;
            }

            if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_BUF_ERROR) {
                inflateEnd(&strm);
                r.info = "Invalid GZIP: inflate failed (data/buf/mem error)";
                r.length = blob.size() - offset;
                return r;
            }

            size_t have = buffer.size() - strm.avail_out;
            if (have > 0) {
                crc32Calc = crc32(crc32Calc, buffer.data(), have);
                isizeCalc += have;
            }

        } while (ret != Z_STREAM_END);

        inflateEnd(&strm);


        bool crcMatch = (crc32Calc == crc32Trailer);
        bool sizeMatch = (isizeCalc == isizeTrailer);

        info << ", recomputed CRC32=0x" << std::hex << crc32Calc
             << ", recomputed ISIZE=" << std::dec << isizeCalc;

        if (crcMatch && sizeMatch) {
            info << " (validated)";
            r.isValid = true;
        } else {
            info << " (validation failed)";
            r.isValid = false;
        }

        r.length = blob.size() - offset;
        r.info = info.str();
        return r;
    }
};

REGISTER_PARSER(GzipParser)
