#pragma once
#include "scanresult.hpp"
void printResult(const ScanResult& result, int depth = 0);
void dumpJson(const std::vector<ScanResult>& results,std::string filename);
void printTree(const ScanResult& node, const std::string& prefix = "", bool isLast = true);
void printScanResults(const std::vector<ScanResult>& results,std::string inputFile);