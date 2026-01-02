#pragma once
#include "parsers/base_parser.hpp"
#include "extractors/base_extractor.hpp"
#include <vector>
#include <memory>
#include <tuple>
#include <unordered_set>
#include <filesystem>
#include "scanresult.hpp"
namespace fs = std::filesystem;
class Scanner {
public:
    bool enableExtraction = false;
    int recursionDepth = 1;
    int currentDepth = 0;
    bool verbose = false;

    std::vector<ScanResult> results;
    std::unordered_set<size_t> visitedOffsets;
    std::vector<std::string> alreadyAnalyzed;
    Scanner(bool enableExtraction, int recursionDepth, int currentDepth = 0,fs::path extractionPath = "extractions/",bool verbose = false);
    std::vector<ScanResult> scan(fs::path filePath);

    //void printResult(const ScanResult& result, int depth);
    Scanner * parent = nullptr;
    fs::path extractionPath;
private:
    std::vector<std::unique_ptr<BaseParser>> parsers;
    std::vector<std::unique_ptr<BaseExtractor>> extractors;
};