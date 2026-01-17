#include "scanner.hpp"
#include "utils/file_reader.hpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <fstream>
#include "logger.hpp"
#include <chrono>
#include "utils/printer.hpp"

namespace fs = std::filesystem;
struct Config {
    bool extract = false;
    int recurseDepth = 0;
    bool jsonOutput = false;        // keep as flag if you want
    std::string jsonFile;      // new field
    bool verbose = false;
    std::string extractionPath = "extractions/";
    std::string inputFile;
};


class ArgParser {
public:
    struct OptionInfo {
        bool takesValue;
        std::string canonicalName;
    };

    std::unordered_map<std::string, OptionInfo> optionDefs;
    std::unordered_map<std::string, std::string> parsedOptions;
    std::vector<std::string> positional;

    void addOption(const std::string& name, bool takesValue, const std::string& canonical) {
        optionDefs[name] = {takesValue, canonical};
    }

    void parse(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            // Is this a known option?
            if (optionDefs.count(arg)) {
                const auto& info = optionDefs[arg];

                if (info.takesValue) {
                    if (i + 1 >= argc) {
                        throw std::runtime_error("Missing value for option: " + arg);
                    }
                    parsedOptions[info.canonicalName] = argv[++i];
                } else {
                    parsedOptions[info.canonicalName] = "true";
                }
            }
            else {
                // Not an option → positional argument
                positional.push_back(arg);
            }
        }
    }

    bool has(const std::string& canonical) const {
        return parsedOptions.count(canonical);
    }

    std::string get(const std::string& canonical, const std::string& def = "") const {
        auto it = parsedOptions.find(canonical);
        return it != parsedOptions.end() ? it->second : def;
    }
};



Config parseArgs(int argc, char* argv[]) {

    Config config;
    ArgParser args;
    args.addOption("-h", false, "help"); 
    args.addOption("--help", false, "help");

    args.addOption("-e", false, "extract"); 
    args.addOption("--extract", false, "extract");

    args.addOption("-d", false, "debug"); 
    args.addOption("--debug", false, "debug");

    args.addOption("-v", false, "verbose"); 
    args.addOption("--verbose", false, "verbose");

    args.addOption("-C", true, "extractionPath"); 
    args.addOption("--extractionPath", true, "extractionPath");

    args.addOption("-O", true, "jsonPath"); 
    args.addOption("--jsonPath", true, "jsonPath");

    args.addOption("-r", true, "recurse"); 
    args.addOption("--recurse", true, "recurse");

    args.parse(argc,argv);

    

    if(args.has("extract"))
    {
       Logger::debug("Enabling extraction");
        config.extract = true;
        config.recurseDepth = 1; 
    }

    if(args.has("debug"))
    {
       Logger::info("Enabling Debug Mode");
            Logger::setLevel(LogLevel::DEBUG);
    }

    if(args.has("verbose"))
    {
       Logger::debug("Enabling verbose Output");
        config.verbose = true;
    }

    if(args.has("recurse"))
    {
       config.recurseDepth = std::stoi(args.get("recurse"));
        if (config.recurseDepth < 1)
        {
            config.recurseDepth = 1;
        }
     
        Logger::debug("Setting recurse depth to "+ std::to_string(config.recurseDepth));
    }

    if(args.has("extractionPath"))
    {
       config.extractionPath = args.get("extractionPath");
 
     
        Logger::debug("Setting extraction path to "+ config.extractionPath);
    }

    if(args.has("jsonPath"))
    {
       config.jsonFile = args.get("jsonPath");
        config.jsonOutput = true;
     
        Logger::debug("Setting json output path to "+ config.jsonFile);
    }

    if(args.has("help") || args.positional.empty())
    {
        std::cout << "Usage: scanner [-e] [-r N or -rN] [-j [file]] <input_file>\n"
                      << "  -e         Enable extraction\n"
                      << "  -r N       Enable recursive scan with depth N (default 1)\n"
                      << "  -O [file]  Output in JSON format, optionally to given file\n"
                      << "  -C [path]  Custom extraction path\n"
                      << "  -d         Enable Debug mode\n"
                      << "  -v         Verbose output\n"
                      << "  -h         Show this help message\n";
        std::exit(0);
    }

 
   
    config.inputFile = args.positional.back();
    
    return config;
}

int main(int argc, char* argv[]) {
    Logger::setLevel(LogLevel::INFO);
    Logger::info("HexDig v0.1");
    
    Config config = parseArgs(argc, argv);

    Scanner scanner(config.extract, config.recurseDepth,0,fs::path(config.extractionPath),config.verbose);
    Logger::info("Opening " + config.inputFile + "...");
    
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
