#include "helpers.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <charconv>
#include <array>
//
// Big-endian readers
//
 uint16_t read_be16(const std::vector<uint8_t>& blob, size_t offset) {
    return (blob[offset] << 8) |
           (blob[offset + 1]);
}

 uint32_t read_be32(const std::vector<uint8_t>& blob, size_t offset) {
    return (blob[offset] << 24) |
           (blob[offset + 1] << 16) |
           (blob[offset + 2] << 8) |
           (blob[offset + 3]);
}

 uint64_t read_be64(const std::vector<uint8_t>& blob, size_t offset) {
    return (static_cast<uint64_t>(blob[offset]) << 56) |
           (static_cast<uint64_t>(blob[offset + 1]) << 48) |
           (static_cast<uint64_t>(blob[offset + 2]) << 40) |
           (static_cast<uint64_t>(blob[offset + 3]) << 32) |
           (static_cast<uint64_t>(blob[offset + 4]) << 24) |
           (static_cast<uint64_t>(blob[offset + 5]) << 16) |
           (static_cast<uint64_t>(blob[offset + 6]) << 8)  |
           (static_cast<uint64_t>(blob[offset + 7]));
}

//
// Little-endian readers
//
 uint16_t read_le16(const std::vector<uint8_t>& blob, size_t offset) {
    return (blob[offset + 1] << 8) |
           (blob[offset]);
}

 uint32_t read_le32(const std::vector<uint8_t>& blob, size_t offset) {
    return (blob[offset + 3] << 24) |
           (blob[offset + 2] << 16) |
           (blob[offset + 1] << 8) |
           (blob[offset]);
}

 uint64_t read_le64(const std::vector<uint8_t>& blob, size_t offset) {
    return (static_cast<uint64_t>(blob[offset + 7]) << 56) |
           (static_cast<uint64_t>(blob[offset + 6]) << 48) |
           (static_cast<uint64_t>(blob[offset + 5]) << 40) |
           (static_cast<uint64_t>(blob[offset + 4]) << 32) |
           (static_cast<uint64_t>(blob[offset + 3]) << 24) |
           (static_cast<uint64_t>(blob[offset + 2]) << 16) |
           (static_cast<uint64_t>(blob[offset + 1]) << 8)  |
           (static_cast<uint64_t>(blob[offset]));
}

//
// Null-terminated string reader
//
 std::string read_string(const std::vector<uint8_t>& blob, size_t offset, size_t maxLength) {
    std::string result;
    for (size_t i = 0; i < maxLength && offset + i < blob.size(); ++i) {
        char c = static_cast<char>(blob[offset + i]);
        if (c == '\0') break;
        result += c;
    }
    return result;
}

std::string format_timestamp(uint32_t ts) {
    std::time_t t = static_cast<std::time_t>(ts);
    std::tm* gmt = std::gmtime(&t);
    std::ostringstream oss;
    oss << std::put_time(gmt, "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}




std::string to_hex(int value)
{
   std::array<char, 16> buffer;
   auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(),
                              value, 16);  // base 16

   std::string hex(buffer.data(), result.ptr);
   return hex;
}

// CRC-16/ARC (polynomial 0xA001, initial value 0x0000)
uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0x0000;

    while (len--) {
        crc ^= *data++;
        for (int i = 0; i < 8; i++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xA001;
            else
                crc >>= 1;
        }
    }

    return crc;
}

// ----------------------------------------------------------------------------
// 7-Zip locator
// ----------------------------------------------------------------------------
#include <filesystem>
#include <initializer_list>

#ifdef _WIN32
  #include <windows.h>
#elif defined(__APPLE__)
  #include <mach-o/dyld.h>
  #include <climits>
#else
  #include <unistd.h>
  #include <climits>
#endif

namespace {
std::filesystem::path executable_dir() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return {};
    return std::filesystem::path(buf).parent_path();
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) return {};
    std::error_code ec;
    auto p = std::filesystem::canonical(buf, ec);
    return ec ? std::filesystem::path{} : p.parent_path();
#else
    std::error_code ec;
    auto p = std::filesystem::canonical("/proc/self/exe", ec);
    return ec ? std::filesystem::path{} : p.parent_path();
#endif
}
} // namespace

std::string find_7z() {
    static std::string cached;
    if (!cached.empty()) return cached;

#ifdef _WIN32
    const std::initializer_list<const char*> bundled = {"7zr.exe", "7za.exe", "7z.exe"};
    const char* fallback = "7z";
#else
    const std::initializer_list<const char*> bundled = {"7zz", "7z"};
    const char* fallback = "7zz";
#endif

    auto dir = executable_dir();
    if (!dir.empty()) {
        for (auto name : bundled) {
            std::error_code ec;
            auto candidate = dir / name;
            if (std::filesystem::exists(candidate, ec)) {
                // Quote so paths with spaces survive shell expansion.
                cached = "\"" + candidate.string() + "\"";
                return cached;
            }
        }
    }

    // Nothing bundled — rely on the OS PATH lookup performed by std::system().
    cached = fallback;
    return cached;
}

bool is_7z_available() {
    static int cached = -1;  // -1 = unknown, 0 = no, 1 = yes
    if (cached != -1) return cached == 1;

    auto loc = find_7z();
    // find_7z returns a quoted absolute path when a bundled binary was found.
    if (!loc.empty() && loc.front() == '"') { cached = 1; return true; }

    // Otherwise it returned a bare command name; walk PATH to verify.
    const char* pathEnv = std::getenv("PATH");
    if (!pathEnv) { cached = 0; return false; }

#ifdef _WIN32
    const char sep = ';';
    const std::initializer_list<const char*> names = {"7z.exe", "7za.exe", "7zr.exe"};
#else
    const char sep = ':';
    const std::initializer_list<const char*> names = {"7zz", "7z"};
#endif

    std::string path(pathEnv);
    size_t start = 0;
    while (start <= path.size()) {
        size_t end = path.find(sep, start);
        std::string dir = path.substr(start, end - start);
        if (!dir.empty()) {
            for (auto name : names) {
                std::error_code ec;
                if (std::filesystem::exists(std::filesystem::path(dir) / name, ec)) {
                    cached = 1;
                    return true;
                }
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    cached = 0;
    return false;
}

#ifdef _WIN32
#include <vector>
#endif

int run_command(const std::string& cmd) {
#ifdef _WIN32
    // Build "cmd.exe /c <command>" so shell features (redirection, internal quoting) work,
    // then run it via CreateProcessW with CREATE_NO_WINDOW to suppress the console flash.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return -1;
    std::vector<wchar_t> wcmd(wlen);
    MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, wcmd.data(), wlen);

    std::wstring fullCmd;
    fullCmd.reserve(wcmd.size() + 16);
    fullCmd = L"cmd.exe /c \"";
    fullCmd += wcmd.data();
    fullCmd += L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        nullptr,
        fullCmd.data(),     // mutable buffer required by CreateProcessW
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);
    if (!ok) return -1;

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
#else
    int rc = std::system(cmd.c_str());
    if (rc == -1) return rc;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
#endif
}

