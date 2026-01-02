#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include <filesystem>
namespace fs = std::filesystem;


class BaseExtractor {
public:
    virtual ~BaseExtractor() = default;
    virtual std::string name() const = 0;
    virtual void extract(const std::vector<std::uint8_t>& blob, size_t offset,fs::path extractionPath) = 0;
};