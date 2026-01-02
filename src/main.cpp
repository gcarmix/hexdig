#include "scanner.hpp"
#include "utils/file_reader.hpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <fstream>
#include "logger.hpp"
#include <chrono>
#include "utils/printer.hpp"

namespace fs = std::filesystem;
struct Config {
    bool extract = false;
    int recurseDepth = 0;
    int jsonOutput = 0;        // keep as flag if you want
    std::string jsonFile;      // new field
    bool verbose = false;
    std::string inputFile;
};

Config parseArgs(int argc, char* argv[]) {
    Config config;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-e") {
            Logger::debug("Enabling extraction");
            config.extract = true;
            config.recurseDepth = 1;
        } else if (arg == "-r") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config.recurseDepth = std::stoi(argv[++i]);
                if (config.recurseDepth < 1)
                {
                    config.recurseDepth = 1;
                }
            } else {
                config.recurseDepth = 1;
            }
            Logger::debug("Setting recurse depth to "+ std::to_string(config.recurseDepth));
        } else if (arg.size() >= 2 && arg.substr(0, 2) == "-r") {
            config.recurseDepth = std::stoi(arg.substr(2));
            Logger::debug("Setting recurse depth to "+ std::to_string(config.recurseDepth));
        } else if (arg == "-j") {
            config.jsonOutput = 1;
            Logger::debug("Enabling json output");
            // Look ahead for optional filename
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config.jsonFile = argv[++i];
            }
        } else if (arg == "-v") {
            Logger::debug("Enabling verbose Output");
            config.verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: scanner [-e] [-r N or -rN] [-j [file]] <input_file>\n"
                      << "  -e         Enable extraction\n"
                      << "  -r N       Enable recursive scan with depth N (default 1)\n"
                      << "  -j [file]  Output in JSON format, optionally to given file\n"
                      << "  -v         Verbose output\n"
                      << "  -h         Show this help message\n";
            std::exit(0);
        } else if (!arg.empty() && arg[0] != '-') {
            positional.push_back(arg);
        }
    }

    if (positional.empty()) {
        std::cerr << "Error: Missing input file.\n";
        std::exit(1);
    }

    config.inputFile = positional[0];
    return config;
}

int main(int argc, char* argv[]) {
    Logger::setLevel(LogLevel::DEBUG);
    Logger::info("HexDig v0.1");
    Config config = parseArgs(argc, argv);

    Scanner scanner(config.extract, config.recurseDepth,0,fs::path("extractions/"),config.verbose);
    Logger::debug("Opening " + config.inputFile + "...");
    
    auto start = std::chrono::high_resolution_clock::now();
    auto results = scanner.scan(fs::path(config.inputFile));
    printScanResults(results,config.inputFile);
    if(config.jsonOutput)
        dumpJson(results,config.jsonFile);

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    Logger::info("Total elapsed time: " + std::to_string(elapsed) + "ms");

    return 0;
}
