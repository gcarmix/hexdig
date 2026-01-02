#pragma once
#include <vector>
#include <string>
#include <tuple>
#include <cstdint>
#include "scanresult.hpp"


class BaseParser {
public:
    virtual ~BaseParser() = default;
    virtual std::string name() const = 0;
    virtual bool match(const std::vector<std::uint8_t>& blob, size_t offset) = 0;
    virtual ScanResult parse(const std::vector<std::uint8_t>& blob, size_t offset) = 0;

};
