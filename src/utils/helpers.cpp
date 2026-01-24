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
