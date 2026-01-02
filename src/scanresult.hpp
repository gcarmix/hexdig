#pragma once
#include <string>
#include <vector>
#include <iostream>

struct ScanResult {
    size_t offset;
    std::string type;
    std::string extractorType;
    size_t length;
    std::string info;
    std::string source;  // NEW: e.g., "ZIP:images/logo.jpg"
    std::vector<ScanResult> children;  // 🧠 Nested scan results
    bool confident = true;
    bool isValid = false;
};
