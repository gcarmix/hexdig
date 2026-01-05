#include<iostream>
#include "printer.hpp"
#include "helpers.hpp"
#include "cJSON.h"
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <fstream>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;
cJSON* build_json_result(const ScanResult& r) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "offset", to_hex(r.offset).c_str());
    cJSON_AddStringToObject(item, "type", r.type.c_str());
    cJSON_AddNumberToObject(item, "size", static_cast<double>(r.length));
    cJSON_AddStringToObject(item, "source", r.source.c_str());
    cJSON_AddStringToObject(item, "info", r.info.c_str());

    if (!r.children.empty()) {
        cJSON* childArray = cJSON_CreateArray();
        for (const auto& child : r.children) {
            cJSON_AddItemToArray(childArray, build_json_result(child));
        }
        cJSON_AddItemToObject(item, "children", childArray);
    }

    return item;
}

void dumpJson(const std::vector<ScanResult>& results,std::string filename) {
    fs::path outputPath = fs::path(filename);
    std::ofstream outFile(outputPath, std::ios::binary);
    if (outFile.is_open()) {
        cJSON* root = cJSON_CreateArray();
        for (const auto& r : results) {
            cJSON_AddItemToArray(root, build_json_result(r));
        }

        char* jsonStr = cJSON_Print(root);
        outFile.write(reinterpret_cast<const char*>(jsonStr), strlen(jsonStr));
        outFile.close();
        cJSON_Delete(root);
        free(jsonStr);


        
    }
    
}

void printResult(const ScanResult& result, int depth) {
    std::cout<<"+-";
    for (int i=0;i<depth;i++) std::cout<<"-";
    //std::string indent(depth * 2, '\t');
    std::cout << "0x" << std::hex << result.offset
              << "\t\t[" << result.type<<"]"
              << "\t\t" << std::dec << result.length;
    std::cout << "\t\t" << result.info.substr(0,16)<< "\n";

   /* for (const auto& child : result.children) {
        printResult(child, depth + 1);
    }*/
}

// ANSI color codes
namespace ansi {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string cyan    = "\033[36m";
    const std::string yellow  = "\033[33m";
    const std::string green   = "\033[32m";
    const std::string magenta = "\033[35m";
    const std::string gray    = "\033[90m";
}




// Wrap long text into multiple lines with indentation
static std::vector<std::string> wrapText(const std::string& text, size_t width) {
    std::vector<std::string> lines;
    std::istringstream words(text);
    std::string word, line;
    while (words >> word) {
        if (line.size() + word.size() + 1 > width) {
            lines.push_back(line);
            line.clear();
        }
        if (!line.empty()) line += " ";
        line += word;
    }
    if (!line.empty()) lines.push_back(line);
    return lines;
}

static void printScanResult(const ScanResult& sr, const std::string& prefix = "", bool last = true) {
    // Offset in cyan, type in bold yellow, length in green
    std::ostringstream oss;
    oss << ansi::cyan << "[0x" << std::hex << std::setw(4) << std::setfill('0') << sr.offset << "]" << ansi::reset
        << " " << ansi::bold << ansi::yellow << sr.type << ansi::reset
        << " (length=" << ansi::green << std::dec << sr.length << ansi::reset << ")";

    std::cout << prefix << (last ? "└── " : "├── ") << oss.str() << "\n";

    // Prepare child prefix
    std::string childPrefix = prefix + (last ? "    " : "│   ");

    // Source in magenta
    if (!sr.source.empty()) {
        std::cout << childPrefix << ansi::magenta << "Source: " << sr.source << ansi::reset << "\n";
    }

    // Info wrapped, in gray
    if (!sr.info.empty()) {
        auto lines = wrapText(sr.info, 60);
        if (!lines.empty()) {
            std::cout << childPrefix << ansi::gray << "Info: " << lines[0] << ansi::reset << "\n";
            for (size_t i = 1; i < lines.size(); ++i) {
                std::cout << childPrefix << ansi::gray << "      " << lines[i] << ansi::reset << "\n";
            }
        }
    }

    // Children recursively
    for (size_t i = 0; i < sr.children.size(); ++i) {
        printScanResult(sr.children[i], childPrefix, i == sr.children.size() - 1);
    }
}

// Entry point: print a vector of ScanResult
void printScanResults(const std::vector<ScanResult>& results,std::string inputFile) {
    std::cout<<"* "<<inputFile<<std::endl;
    for (size_t i = 0; i < results.size(); ++i) {
        printScanResult(results[i], "", i == results.size() - 1);
    }
}
