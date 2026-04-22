#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include "helpers.hpp"
#include "logger.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <cstdint>
#include <cctype>
#include <algorithm>

namespace fs = std::filesystem;

// UBI extractor — reconstructs logical volumes from a UBI image.
//
// A UBI image is a sequence of Physical Erase Blocks (PEBs). Each data PEB
// carries two headers:
//   - EC header  at PEB + 0                 (magic "UBI#")
//   - VID header at PEB + vid_hdr_offset    (magic "UBI!")
// and a payload from PEB + data_offset to the end of the PEB. The VID header
// tells us which volume (vol_id) a PEB belongs to and which logical block
// (lnum) inside that volume. We walk all PEBs, group them by vol_id, order
// the LEBs by lnum, and emit one file per volume. Volume names are read from
// the layout volume (vol_id 0x7FFFEFFF) when present.

static constexpr uint32_t UBI_EC_MAGIC    = 0x55424923; // "UBI#"
static constexpr uint32_t UBI_VID_MAGIC   = 0x55424921; // "UBI!"
static constexpr size_t   UBI_EC_HDR_SIZE  = 64;
static constexpr size_t   UBI_VID_HDR_SIZE = 64;
static constexpr uint32_t UBI_LAYOUT_VOL_ID    = 0x7FFFEFFF;
static constexpr uint32_t UBI_INTERNAL_VOL_MIN = 0x7FFFF000;
static constexpr size_t   UBI_VTBL_REC_SIZE = 172;
static constexpr size_t   UBI_MAX_VOLUMES   = 128;

struct Leb {
    uint32_t lnum;
    uint64_t sqnum;
    uint32_t data_size; // 0 means "full LEB" (dynamic volumes)
    size_t   src_offset;
    size_t   src_length;
};

class UBIExtractor : public BaseExtractor {
public:
    std::string name() const override { return "UBI"; }

    void extract(const std::vector<uint8_t>& blob,
                 size_t offset,
                 fs::path extractionPath) override
    {
        if (offset + UBI_EC_HDR_SIZE > blob.size()) {
            Logger::error("UBI: offset beyond blob size");
            return;
        }
        if (read_be32(blob, offset) != UBI_EC_MAGIC) {
            Logger::error("UBI: EC magic mismatch at offset");
            return;
        }

        // Read data_offset / vid_hdr_offset from first EC header (they are
        // expected to be constant across an image).
        uint32_t vid_hdr_off = read_be32(blob, offset + 16);
        uint32_t data_off    = read_be32(blob, offset + 20);

        size_t pebSize = detectPebSize(blob, offset);
        if (pebSize == 0) {
            Logger::error("UBI: could not detect PEB size");
            return;
        }
        if (data_off == 0 || data_off >= pebSize ||
            vid_hdr_off < UBI_EC_HDR_SIZE || vid_hdr_off + UBI_VID_HDR_SIZE > pebSize) {
            Logger::error("UBI: implausible header offsets");
            return;
        }

        fs::create_directories(extractionPath);
        extractionPath /= fs::path(to_hex(offset));
        fs::create_directories(extractionPath);

        // Walk PEBs, collect LEBs per volume.
        std::map<uint32_t, std::map<uint32_t, Leb>> vols; // vol_id -> lnum -> Leb
        size_t pos = offset;
        size_t pebCount = 0;
        while (pos + pebSize <= blob.size()) {
            uint32_t ec_magic = read_be32(blob, pos);
            if (ec_magic != UBI_EC_MAGIC) {
                // Allow erased PEBs inside the image; stop otherwise.
                bool erased = true;
                for (size_t i = 0; i < UBI_EC_HDR_SIZE; i++) {
                    if (blob[pos + i] != 0xFF) { erased = false; break; }
                }
                if (!erased) break;
                pos += pebSize;
                pebCount++;
                continue;
            }

            size_t vid_pos = pos + vid_hdr_off;
            if (read_be32(blob, vid_pos) == UBI_VID_MAGIC) {
                // ubi_vid_hdr layout (big-endian):
                //   0  magic (4) "UBI!"
                //   4  version (1)
                //   5  vol_type (1)  1=dynamic 2=static
                //   6  copy_flag (1)
                //   7  compat (1)
                //   8  vol_id (4)
                //  12  lnum (4)
                //  16  padding1 (4)
                //  20  data_size (4)
                //  24  used_ebs (4)
                //  28  data_pad (4)
                //  32  data_crc (4)
                //  36  padding2 (4)
                //  40  sqnum (8)
                //  48  padding3 (12)
                //  60  hdr_crc (4)
                uint32_t vol_id    = read_be32(blob, vid_pos + 8);
                uint32_t lnum      = read_be32(blob, vid_pos + 12);
                uint32_t data_size = read_be32(blob, vid_pos + 20);
                uint32_t data_pad  = read_be32(blob, vid_pos + 28);
                uint64_t sqnum     = read_be64(blob, vid_pos + 40);

                size_t leb_src = pos + data_off;
                size_t leb_cap = pebSize - data_off;
                if (data_pad < leb_cap) leb_cap -= data_pad;

                Leb leb;
                leb.lnum       = lnum;
                leb.sqnum      = sqnum;
                leb.data_size  = data_size;
                leb.src_offset = leb_src;
                leb.src_length = leb_cap;

                auto& vol = vols[vol_id];
                auto it = vol.find(lnum);
                if (it == vol.end() || sqnum > it->second.sqnum) {
                    vol[lnum] = leb;
                }
            }

            pos += pebSize;
            pebCount++;
        }

        if (vols.empty()) {
            Logger::error("UBI: no volumes found");
            return;
        }

        std::map<uint32_t, std::string> volNames = parseVolumeNames(blob, vols);

        for (auto& [vol_id, lebs] : vols) {
            // Skip internal volumes other than the layout volume; keep the
            // layout volume as raw output for inspection.
            if (vol_id >= UBI_INTERNAL_VOL_MIN && vol_id != UBI_LAYOUT_VOL_ID) {
                continue;
            }

            std::string volName;
            auto nameIt = volNames.find(vol_id);
            if (nameIt != volNames.end() && !nameIt->second.empty()) {
                volName = sanitizeName(nameIt->second);
            }
            if (volName.empty()) {
                if (vol_id == UBI_LAYOUT_VOL_ID) {
                    volName = "layout";
                } else {
                    volName = "vol_" + std::to_string(vol_id);
                }
            }

            fs::path outPath = extractionPath / (volName + ".img");
            std::ofstream out(outPath, std::ios::binary);
            if (!out) {
                Logger::error("UBI: cannot write " + outPath.string());
                continue;
            }

            size_t totalBytes = 0;
            for (auto& [lnum, leb] : lebs) {
                size_t len = leb.src_length;
                // Static volumes carry a real payload size; dynamic volumes
                // leave data_size at zero meaning "full LEB".
                if (leb.data_size > 0 && leb.data_size < len) {
                    len = leb.data_size;
                }
                if (leb.src_offset + len > blob.size()) {
                    len = (leb.src_offset < blob.size())
                        ? blob.size() - leb.src_offset : 0;
                }
                if (len == 0) continue;
                out.write(reinterpret_cast<const char*>(&blob[leb.src_offset]), len);
                totalBytes += len;
            }
            Logger::debug("UBI: wrote " + outPath.string() +
                          " (" + std::to_string(totalBytes) + " bytes, " +
                          std::to_string(lebs.size()) + " LEBs)");
        }

        Logger::debug("UBI: processed " + std::to_string(pebCount) + " PEBs, " +
                      std::to_string(vols.size()) + " volumes");
    }

private:
    static size_t detectPebSize(const std::vector<uint8_t>& blob, size_t offset) {
        static const size_t candidates[] = {
            0x4000, 0x8000, 0x10000, 0x20000,
            0x40000, 0x80000, 0x100000, 0x200000
        };
        for (size_t cand : candidates) {
            size_t next = offset + cand;
            if (next + 4 > blob.size()) continue;
            if (read_be32(blob, next) == UBI_EC_MAGIC) return cand;
        }
        return 0;
    }

    // Parse the layout volume (vol_id 0x7FFFEFFF) to map vol_id -> volume
    // name. The layout volume holds up to 128 ubi_vtbl_record entries of
    // 172 bytes each; entries whose name_len == 0 are empty slots.
    static std::map<uint32_t, std::string> parseVolumeNames(
        const std::vector<uint8_t>& blob,
        const std::map<uint32_t, std::map<uint32_t, Leb>>& vols)
    {
        std::map<uint32_t, std::string> out;
        auto it = vols.find(UBI_LAYOUT_VOL_ID);
        if (it == vols.end() || it->second.empty()) return out;

        // Layout LEB 0 is the authoritative copy.
        const Leb& leb = it->second.begin()->second;
        size_t base = leb.src_offset;
        size_t cap  = leb.src_length;
        if (base + cap > blob.size()) {
            cap = (base < blob.size()) ? blob.size() - base : 0;
        }

        for (size_t i = 0; i < UBI_MAX_VOLUMES; i++) {
            size_t off = i * UBI_VTBL_REC_SIZE;
            if (off + UBI_VTBL_REC_SIZE > cap) break;

            size_t rec = base + off;
            uint16_t name_len = read_be16(blob, rec + 14);
            if (name_len == 0 || name_len > 127) continue;

            std::string name;
            name.reserve(name_len);
            for (size_t k = 0; k < name_len; k++) {
                char c = static_cast<char>(blob[rec + 16 + k]);
                if (c == '\0') break;
                name.push_back(c);
            }
            if (!name.empty()) out[static_cast<uint32_t>(i)] = name;
        }
        return out;
    }

    static std::string sanitizeName(const std::string& in) {
        std::string out;
        out.reserve(in.size());
        for (char c : in) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (std::isalnum(uc) || c == '_' || c == '-' || c == '.') {
                out.push_back(c);
            } else {
                out.push_back('_');
            }
        }
        // Avoid leading dot (would hide the file) and empty result.
        if (!out.empty() && out.front() == '.') out.front() = '_';
        return out;
    }
};

REGISTER_EXTRACTOR(UBIExtractor)
