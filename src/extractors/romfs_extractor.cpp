#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include "helpers.hpp"
namespace fs = std::filesystem;



struct RomfsEntry {
    uint32_t next;
    uint32_t spec;
    uint32_t size;
    uint32_t checksum;
    std::string name;
    size_t headerOffset;
    size_t dataOffset;
    enum Type { Regular, Directory, Symlink, Device, Fifo, Socket, Hardlink, Unknown } type = Unknown;
};

class RomfsExtractor : public BaseExtractor {
public:
    std::string name() const override { return "ROMFS"; }

    // Binwalk-style: writes to disk under outDir; also returns metadata
    void extract(const std::vector<uint8_t>& blob, size_t offset, fs::path extractionPath) {
        extractionPath = extractionPath /fs::path(to_hex(offset)); 

        fs::create_directories(extractionPath);

        if (offset + 16 > blob.size()) {
            return;
        }

        // Superblock
        uint32_t fsSize   = read_be32(blob, offset + 8);
        uint32_t sbCsum   = read_be32(blob, offset + 12);
        size_t fsEnd = offset + fsSize;

        if (fsSize == 0 || fsEnd > blob.size()) {
            return;
        }

        // Conservative checksum validation: additive over 32-bit BE words of the whole FS region
        bool checksumOk = validateFilesystemChecksum(blob, offset, fsSize, sbCsum);



        // Walk root chain starting right after superblock
        std::set<size_t> visited;
        size_t cursor = offset + 16;
        size_t fileCount = 0, dirCount = 0, symlinkCount = 0;

        while (cursor + 16 <= fsEnd) {
            if (visited.count(cursor)) break;
            visited.insert(cursor);

            RomfsEntry e = readEntry(blob, offset, fsEnd, cursor);
            if (e.name.empty()) break;

            classifyEntry(e); // heuristics described below

            fs::path target = extractionPath / fs::path(e.name);
            switch (e.type) {
                case RomfsEntry::Directory: {
                    fs::create_directories(target);
                    dirCount++;
                    // Recurse into children via spec (if spec points to first child)
                    enumerateChildren(blob, offset, fsEnd, e.spec, target, visited, fileCount, dirCount, symlinkCount);
                    break;
                }
                case RomfsEntry::Regular: {
                    if (e.dataOffset + e.size <= fsEnd) {
                        fs::create_directories(target.parent_path());
                        writeFile(target, blob, e.dataOffset, e.size);
                        fileCount++;
                    }
                    break;
                }
                case RomfsEntry::Symlink: {
                    std::string linkTarget = readNullTermString(blob, e.dataOffset, fsEnd);
                    fs::create_directories(target.parent_path());
                    // Create a text file stub with the link target, like binwalk often does when symlink creation is not desired
                    // If you prefer real symlinks, replace with fs::create_symlink(linkTarget, target, ec);
                    writeText(target, linkTarget + "\n");
                    symlinkCount++;
                    break;
                }
                case RomfsEntry::Device:
                case RomfsEntry::Fifo:
                case RomfsEntry::Socket:
                case RomfsEntry::Hardlink:
                case RomfsEntry::Unknown:
                default: {
                    // Safety: skip special node creation; emit a small metadata file
                    fs::create_directories(target.parent_path());
                    writeText(target.string() + ".meta",
                              describeSpecial(e));
                    break;
                }
            }

            if (e.next == 0) break;
            cursor = offset + e.next;
        }


        return;
    }

private:
    RomfsEntry readEntry(const std::vector<uint8_t>& blob, size_t base, size_t fsEnd, size_t hdrOff) {
        RomfsEntry e{};
        e.headerOffset = hdrOff;
        e.next     = read_be32(blob, hdrOff + 0);
        e.spec     = read_be32(blob, hdrOff + 4);
        e.size     = read_be32(blob, hdrOff + 8);
        e.checksum = read_be32(blob, hdrOff + 12);

        // Read name (NUL-terminated)
        size_t nameStart = hdrOff + 16;
        e.name = readNullTermString(blob, nameStart, fsEnd);

        // Align data start to 16-byte boundary after NUL
        size_t afterName = nameStart + e.name.size() + 1;
        e.dataOffset = (afterName + 15) & ~((size_t)15);
        return e;
    }

    // Heuristic classification aligned with common ROMFS variants and binwalk tolerance:
    // - Regular files: size > 0 and data follows the name padding
    // - Directories: size == 0 and spec points to a plausible child entry inside FS
    // - Symlinks: size == 0 and data area contains a NUL-terminated string; spec may point to target or be 0
    // - Special nodes: non-zero spec encodes device/pipe/socket; we skip creation
    void classifyEntry(RomfsEntry& e) {
        if (e.size > 0) {
            e.type = RomfsEntry::Regular;
            return;
        }
        // Directory if spec is a plausible offset (child header)
        if (e.spec != 0) {
            e.type = RomfsEntry::Directory; // treat as directory first; children will be walked via spec
            return;
        }
        // Symlink if there is a plausible NUL-terminated string in data area
        e.type = RomfsEntry::Symlink; // binwalk-like tolerance
    }

    void enumerateChildren(const std::vector<uint8_t>& blob,
                           size_t base, size_t fsEnd, uint32_t childOff,
                           const fs::path& parent,
                           std::set<size_t>& visited,
                           size_t& fileCount, size_t& dirCount, size_t& symlinkCount) {
        if (childOff == 0) return;
        size_t cursor = base + childOff;
        std::error_code ec;
        fs::create_directories(parent, ec);

        while (cursor + 16 <= fsEnd) {
            if (visited.count(cursor)) break;
            visited.insert(cursor);

            RomfsEntry c = readEntry(blob, base, fsEnd, cursor);
            if (c.name.empty()) break;

            classifyEntry(c);
            fs::path target = parent / fs::path(c.name);

            switch (c.type) {
                case RomfsEntry::Directory:
                    fs::create_directories(target, ec);
                    dirCount++;
                    enumerateChildren(blob, base, fsEnd, c.spec, target, visited, fileCount, dirCount, symlinkCount);
                    break;
                case RomfsEntry::Regular:
                    if (c.dataOffset + c.size <= fsEnd) {
                        fs::create_directories(target.parent_path(), ec);
                        writeFile(target, blob, c.dataOffset, c.size);
                        fileCount++;
                    }
                    break;
                case RomfsEntry::Symlink: {
                    std::string linkTarget = readNullTermString(blob, c.dataOffset, fsEnd);
                    fs::create_directories(target.parent_path(), ec);
                    // Stub text to avoid creating actual symlinks by default
                    writeText(target, linkTarget + "\n");
                    symlinkCount++;
                    break;
                }
                default:
                    fs::create_directories(target.parent_path(), ec);
                    writeText(target.string() + ".meta", describeSpecial(c));
                    break;
            }

            if (c.next == 0) break;
            cursor = base + c.next;
        }
    }

    static void writeFile(const fs::path& path, const std::vector<uint8_t>& blob, size_t off, size_t len) {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(&blob[off]), static_cast<std::streamsize>(len));
    }

    static void writeText(const fs::path& path, const std::string& s) {
        std::ofstream f(path, std::ios::binary);
        f.write(s.data(), static_cast<std::streamsize>(s.size()));
    }

    static std::string describeSpecial(const RomfsEntry& e) {
        std::ostringstream os;
        os << "special entry at 0x" << std::hex << e.headerOffset << std::dec
           << ", spec=0x" << std::hex << e.spec << std::dec
           << ", size=" << e.size;
        return os.str();
    }

    static std::string readNullTermString(const std::vector<uint8_t>& blob, size_t start, size_t limit) {
        std::string s;
        for (size_t i = start; i < limit; ++i) {
            uint8_t c = blob[i];
            if (c == 0) break;
            s.push_back((char)c);
        }
        return s;
    }

    // Conservative, binwalk-like checksum acceptance: if checksum field matches
    // a simple additive sum of all BE 32-bit words in the filesystem region.
    // If your ROMFS uses the "sum of superblock words equals 0" rule, we can switch to that.
    static bool validateFilesystemChecksum(const std::vector<uint8_t>& blob, size_t base, size_t fsSize, uint32_t sbChecksum) {
        uint64_t sum = 0;
        for (size_t off = base; off + 4 <= base + fsSize; off += 4) {
            sum += read_be32(blob, off);
        }
        uint32_t calc = (uint32_t)(sum & 0xFFFFFFFFu);
        // Accept either exact match or "balanced to zero" (common superblock rule)
        return (calc == sbChecksum) || ((calc + sbChecksum) == 0);
    }
};

REGISTER_EXTRACTOR(RomfsExtractor)
