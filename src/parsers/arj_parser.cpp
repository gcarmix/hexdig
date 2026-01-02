#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "helpers.hpp"




class ARJParser : public BaseParser {
public:
    std::string name() const override { return "ARJ"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 2 > blob.size()) return false;
        return read_le16(blob, offset) == 0xEA60;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "ARJ";
        r.extractorType = "7Z";
        r.isValid = false;
        r.length = 0;

        if (offset + 4 > blob.size()) {
            r.info = "Truncated ARJ header";
            r.length = blob.size() - offset;
            return r;
        }

        // Validate magic and main header size
        const uint16_t id = read_le16(blob, offset);
        if (id != 0xEA60) {
            r.info = "Invalid ARJ magic";
            r.length = blob.size() - offset;
            return r;
        }

        const uint16_t mainHeaderSize = read_le16(blob, offset + 2);
        if (offset + 4 + mainHeaderSize > blob.size()) {
            r.info = "Truncated ARJ main header data";
            r.length = blob.size() - offset;
            return r;
        }

        // Extract minimal fields for info (where present)
        uint8_t version = 0, flags = 0;
        if (mainHeaderSize >= 2) {
            version = blob[offset + 4];
            flags   = blob[offset + 5];
        }

        // Cursor to the first file header (after main header)
        size_t cursor = offset + 4 + mainHeaderSize;
        size_t fileCount = 0;
        bool trailerFound = false;

        // Utility: find next header magic safely
        auto findNextHeader = [&](size_t start) -> size_t {
            // Linear scan for 0x60EA without reading past blob
            for (size_t i = start; i + 2 <= blob.size(); ++i) {
                if (read_le16(blob, i) == 0xEA60) return i;
            }
            return blob.size();
        };

        // Walk headers
        while (cursor + 4 <= blob.size()) {
            // Expect header magic
            if (read_le16(blob, cursor) != 0xEA60) {
                // If not a header, attempt to resynchronize by scanning forward
                size_t next = findNextHeader(cursor + 1);
                if (next == blob.size()) break; // no more headers
                cursor = next;
            }

            if (cursor + 4 > blob.size()) break;
            uint16_t hdrSize = read_le16(blob, cursor + 2);

            // Trailer is a header with size==0
            if (hdrSize == 0) {
                trailerFound = true;
                cursor += 4; // trailer header consumes 4 bytes
                break;
            }

            // Ensure header payload fits
            if (cursor + 4 + hdrSize > blob.size()) {
                r.info = "Truncated ARJ file header payload";
                r.length = blob.size() - offset;
                r.isValid = false;
                return r;
            }

            // Try reading compressed size from the header payload when available.
            // Many ARJ variants place compressed size as a 32-bit LE field within the basic header.
            // Heuristic: if hdrSize >= 32, read at offset + 4 + 28 (0x1C) inside this header.
            // If impl differs, we fall back to scanning for the next header magic.
            size_t headerStart = cursor;
            size_t payloadStart = headerStart + 4;
            uint32_t compSize = 0;
            bool haveCompSize = false;

            if (hdrSize >= 32 && payloadStart + 28 + 4 <= blob.size()) {
                compSize = read_le32(blob, payloadStart + 28);
                // Plausibility: non-zero, and not exceeding remaining bytes.
                if (compSize > 0 && payloadStart + hdrSize + compSize <= blob.size()) {
                    haveCompSize = true;
                }
            }

            // Advance past header
            cursor += 4 + hdrSize;

            if (haveCompSize) {
                // Skip file data precisely
                cursor += compSize;
                fileCount++;
            } else {
                // Fallback: resync to next header magic (conservative)
                size_t next = findNextHeader(cursor);
                if (next == cursor) {
                    // Next header immediately follows (0-length file or no data recorded)
                    fileCount++;
                } else if (next < blob.size()) {
                    // Treat bytes until next as file data
                    fileCount++;
                    cursor = next;
                } else {
                    // No further headers; break
                    break;
                }
            }
        }

        // Finalize length: up to trailer if found, else up to last cursor (bounded)
        size_t available = blob.size() - offset;
        size_t parsedLen = cursor > offset ? (cursor - offset) : 0;
        r.length = std::min(parsedLen, available);
        r.isValid = trailerFound && (r.length >= 4 + mainHeaderSize);

        std::ostringstream info;
        info << "ARJ archive, version=" << (int)version
             << ", flags=0x" << std::hex << (int)flags << std::dec
             << ", files=" << fileCount
             << (trailerFound ? ", trailer=OK" : ", trailer=MISSING");
        r.info = info.str();

        return r;
    }
};

REGISTER_PARSER(ARJParser)
