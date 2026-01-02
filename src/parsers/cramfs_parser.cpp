#include "base_parser.hpp"
#include "parser_registration.hpp"
#include <cstdint>
#include <string>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include "cramfs.hpp"
#include "helpers.hpp"
#include "logger.hpp"


class CramFSParser : public BaseParser {
public:
    std::string name() const override { return "CramFS"; }

    bool match(const std::vector<uint8_t>& blob, size_t offset) override {
        if (offset + 8 > blob.size()) return false;
        uint32_t le = read_le32(blob, offset);
        uint32_t be = read_be32(blob, offset);
        return le == 0x28CD3D45u || be == 0x28CD3D45u || le == 0x453DCD28u || be == 0x453DCD28u;
    }

    ScanResult parse(const std::vector<uint8_t>& blob, size_t offset) override {
        ScanResult r;
        r.offset = offset;
        r.type = "CramFS";
        r.isValid = false;
        r.length = 0;

        if (offset + 0x40 > blob.size()) {
            r.info = "Truncated CramFS superblock";
            r.length = blob.size() - offset;
            Logger::error(r.info);
            return r;
        }

        // Detect endianness using magic
        uint32_t magicLE = read_le32(blob, offset);
        uint32_t magicBE = read_be32(blob, offset);
        bool isLE;
        if (magicLE == 0x28CD3D45u || magicLE == 0x453DCD28u) {
            isLE = true;
        } else if (magicBE == 0x28CD3D45u || magicBE == 0x453DCD28u) {
            isLE = false;
        } else {
            r.info = "Invalid CramFS magic";
            r.length = blob.size() - offset;
            Logger::error(r.info);
            return r;
        }

        uint32_t declaredSize = isLE ? read_le32(blob, offset + 4) : read_be32(blob, offset + 4);
        uint32_t flags        = isLE ? read_le32(blob, offset + 8) : read_be32(blob, offset + 8);
        uint32_t future       = isLE ? read_le32(blob, offset + 12) : read_be32(blob, offset + 12);

        // Signature (optional)
        std::string sig;
        for (size_t i = 16; i < 16 + 16; ++i) {
            char c = (char)blob[offset + i];
            if (c == '\0') break;
            if (std::isprint(static_cast<unsigned char>(c))) sig.push_back(c);
        }

        // Sanity checks on superblock
        size_t remaining = blob.size() - offset;
        size_t computedLen = std::min<size_t>(declaredSize, remaining);
        bool plausibleDecl = declaredSize >= 0x40 && declaredSize <= remaining;

        // Parse root inode (expected at offset + 0x40)
        size_t rootInoOff = offset + 0x40;
        if (rootInoOff + 12 > blob.size()) {
            r.info = "Truncated root inode";
            r.length = computedLen;
            r.isValid = false;
            Logger::error(r.info);
            return r;
        }
        CramfsInode root = parseInode(blob, rootInoOff, isLE);

        // Validate root inode
        bool rootIsDir = isDir(root.mode);
        bool rootNameOK = (root.namelen == 0 || (rootInoOff + 12 + root.namelen) <= (offset + declaredSize));
        bool rootOffsetOK = (root.offset < declaredSize);
        bool rootSizeOK = (root.size <= declaredSize);

        // Read root name if present (typically empty)
        std::string rootName;
        if (root.namelen) {
            for (size_t i = 0; i < root.namelen; ++i) {
                rootName.push_back((char)blob[rootInoOff + 12 + i]);
            }
        }

        // Optional sampling of a few entries from root directory table to catch gross errors
        // Root directory entries are located at filesystem start + root.offset.
        // Each entry: [inode (12 bytes)] + [name (namelen bytes)]
        size_t sampleCount = 0;
        size_t dirCursor = offset + root.offset;
        bool dirRegionOK = dirCursor >= offset && dirCursor < (offset + declaredSize);

        bool sampleOK = true;
        if (rootIsDir && dirRegionOK) {
            // Walk up to N entries or until bounds issue; this is a heuristic, not a full walk.
            const size_t MAX_SAMPLE = 8;
            while (sampleCount < MAX_SAMPLE) {
                if (dirCursor + 12 > (offset + declaredSize)) { sampleOK = false; break; }
                CramfsInode child = parseInode(blob, dirCursor, isLE);
                dirCursor += 12;

                // Name bounds
                if (dirCursor + child.namelen > (offset + declaredSize)) { sampleOK = false; break; }

                // Advance over name
                dirCursor += child.namelen;
                sampleCount++;

                // Validate child offsets and sizes within image
                if (child.offset >= declaredSize) { sampleOK = false; break; }
                if (isReg(child.mode) && child.size > declaredSize) { sampleOK = false; break; }

                // Basic type sanity: mode must encode a known file type
                uint16_t ftype = child.mode & 0xF000;
                if (ftype != 0x8000 && ftype != 0x4000 && ftype != 0xA000 && ftype != 0xC000 && ftype != 0x6000 && ftype != 0x2000) {
                    sampleOK = false; break;
                }

                // Heuristic exit if we hit a likely terminator or padding (names of zero length are rare beyond root)
                if (child.namelen == 0) break;
            }
        }

        // Compose info
        std::ostringstream info;
        info << "Compressed ROM File System"
             << ", endianness=" << (isLE ? "LE" : "BE")
             << ", declared size=" << declaredSize
             << ", flags=0x" << std::hex << flags << std::dec
             << ", future=0x" << std::hex << future << std::dec;

        if (!sig.empty()) info << ", signature=\"" << sig << "\"";
        info << ", root: mode=0x" << std::hex << root.mode << std::dec
             << ", uid=" << root.uid << ", gid=" << (int)root.gid
             << ", namelen=" << (int)root.namelen << (rootName.empty() ? "" : (", name=\"" + rootName + "\""))
             << ", offset=" << root.offset << ", size=" << root.size;

        // Final validity
        bool valid = plausibleDecl && rootIsDir && rootNameOK && rootOffsetOK && rootSizeOK && (!root.namelen || rootInoOff + 12 + root.namelen <= offset + declaredSize);
        //if (rootIsDir && dirRegionOK) valid = valid && sampleOK;

        r.info = info.str();
        Logger::debug(r.info);
        r.length = computedLen;
        r.isValid = valid;
        r.extractorType = "7Z";

        return r;
    }
};

REGISTER_PARSER(CramFSParser)
