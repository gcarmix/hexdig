#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>

#define MAX_ANALYZED_FILE_SIZE 1024*1024*1024
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