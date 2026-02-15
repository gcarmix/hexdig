#include "scanner.hpp"
#include "parser_registry.hpp"
#include "extractor_registry.hpp"
#include <iostream>
#include <algorithm>
#include <fstream>
#include "logger.hpp"
#include "printer.hpp"
#include "helpers.hpp"
#include <chrono>

Scanner::Scanner(bool enableExtraction, int recursionDepth, int currentDepth,fs::path extractionPath,bool verbose)
    : enableExtraction(enableExtraction),
      recursionDepth(recursionDepth),
      currentDepth(currentDepth),verbose(verbose){
    parsers = ParserRegistry::instance().createAll();
    extractors = ExtractorRegistry::instance().createAll();
    this->extractionPath = extractionPath;

}


std::vector<ScanResult> Scanner::scan(fs::path filePath) {
    Logger::debug("Scanner::scan " + filePath.string()+"("+std::to_string(currentDepth)+")");
    if(!std::filesystem::is_regular_file(filePath))
    {
        Logger::error("Error, not a regular file");
        return results;
    }
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        Logger::error("Error: Cannot open file " + filePath.string());
        return results;
    }



    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    Logger::debug(std::to_string(size));
    std::vector<uint8_t> blob(size);
    if (!file.read(reinterpret_cast<char*>(blob.data()), size)) {
        throw std::runtime_error("Failed to read file");
    }

    
    size_t offset = 0;
    Logger::debug("BLOB LOADED");
    
    extractionPath = extractionPath / fs::path(filePath.filename().string() + ".extracted");
    int total = 0;
    while (offset < blob.size()) {
        if (visitedOffsets.count(offset)) {
            ++offset;
            continue;
        }
        visitedOffsets.insert(offset);

        bool matched = false;
        for (const auto& parser : parsers) {
            if (parser->match(blob, offset)) {
                Logger::debug(to_hex(offset) + " " + parser->name());
                auto start =  std::chrono::high_resolution_clock::now();
                
                ScanResult result = parser->parse(blob, offset);
                offset = result.offset;
                result.source = filePath.string();
                auto end =  std::chrono::high_resolution_clock::now();
                int diff = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                total += diff;
                Logger::debug(std::to_string(diff));

                result.extracted = false;
                if(result.isValid)
                {

                    if (enableExtraction && recursionDepth > 0) {
                        
                        for (auto& extractor : extractors){
                            if(result.extractorType.compare(extractor->name()) == 0 )
                            {
                                Logger::debug("Using "+extractor->name()+" extractor with path: "+extractionPath.string());
                                Logger::debug(to_hex(offset) + " " + filePath.filename().string());
                                if(extractor->name() == "RAW")
                                {
                                    if(result.length < blob.size())
                                        extractor->extract(blob, offset, extractionPath,result.type);
                                }
                                else
                                {
                                    extractor->extract(blob, offset, extractionPath);
                                }
                                
                                result.extracted = true;

                                if(recursionDepth > 0 && result.extractorType != "RAW")
                                {

                                    std::vector<fs::path> filesToScan;

                                    for (const auto& entry :
                                        fs::recursive_directory_iterator(extractionPath / to_hex(offset)))
                                    {
                                        if (entry.is_regular_file()) {
                                            filesToScan.push_back(entry.path());
                                        }
                                    }

                                    for (const auto& file : filesToScan) {
                                        Logger::debug("SCANREC: " + file.string());

                                        Scanner scanner(true, recursionDepth - 1, currentDepth + 1, file.parent_path());
                                        auto tmpRes = scanner.scan(file);

                                        result.children.insert(
                                            result.children.end(),
                                            std::make_move_iterator(tmpRes.begin()),
                                            std::make_move_iterator(tmpRes.end())
                                        );
                                    }




                                }
                                break;
                            }
                        }
                        
    
                    }

                    if(offset == 0 && result.length == blob.size() && result.extracted == false && !verbose)
                    {
                        Logger::debug("ignoring complete file");
                    }
                    else
                    {
                        Logger::debug("Pushing detected file with offset "+std::to_string(offset)+" len: " + std::to_string(result.length)+ " blob: " + std::to_string(blob.size()));
                        results.push_back(result);
                    }
                    
                    if(result.confident)
                        offset += result.length;
                    matched = true;
                    break;
                }
            }
        }


        if (!matched) {
            ++offset;
        }
    }
    Logger::debug("total: " + std::to_string(total));

    return results;
}
