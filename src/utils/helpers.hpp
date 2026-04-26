#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <initializer_list>


#define MAX_ANALYZED_FILE_SIZE 2*1024*1024*1024UL
//
// Big-endian readers
//
uint16_t read_be16(const std::vector<uint8_t>& blob, size_t offset);
uint32_t read_be32(const std::vector<uint8_t>& blob, size_t offset);
uint64_t read_be64(const std::vector<uint8_t>& blob, size_t offset);

//
// Little-endian readers
//
 uint16_t read_le16(const std::vector<uint8_t>& blob, size_t offset);
 uint32_t read_le32(const std::vector<uint8_t>& blob, size_t offset);
 uint64_t read_le64(const std::vector<uint8_t>& blob, size_t offset);

//
// Null-terminated string reader
//
 std::string read_string(const std::vector<uint8_t>& blob, size_t offset, size_t maxLength);

 std::string format_timestamp(uint32_t ts);
std::string to_hex(int value);

uint16_t crc16(const uint8_t* data, size_t len);

// Locate the 7-Zip command-line binary. Prefers a copy bundled next to the
// running executable (7zr.exe / 7za.exe / 7z.exe on Windows, 7zz / 7z elsewhere)
// and falls back to a system-PATH name. Returns a string suitable for
// substitution into a shell command (already quoted if it contains spaces).
std::string find_7z();

// Returns true if a 7-Zip executable is reachable: either bundled next to the
// running executable or present in the system PATH. Cheap to call (cached).
bool is_7z_available();

// Run a shell command silently and return its exit code.
// On Windows uses CreateProcessW with CREATE_NO_WINDOW so no cmd.exe window flashes.
// On Unix wraps std::system and returns WEXITSTATUS.
int run_command(const std::string& cmd);
