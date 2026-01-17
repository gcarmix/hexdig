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

/*void Scanner::printResult(const ScanResult& result, int depth) {
    std::string indent(depth * 2, ' ');
    std::cout << indent << "↳ Offset: 0x" << std::hex << result.offset
              << ", Type: " << result.type
              << ", Length: " << std::dec << result.length
              << ", Info: " << result.info
              << ", Source: " << result.source << "\n";
}*/

std::vector<ScanResult> Scanner::scan(fs::path filePath) {
    Logger::debug("Scanner::scan " + filePath.string()+"("+std::to_string(currentDepth)+")");
    if(!std::filesystem::is_regular_file(filePath))
    {
        Logger::error("Error, not a regular file");
        return results;
    }
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        Logger::error("Error: Cannot open file " + filePath.string());
        return results;
    }

    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    
    size_t offset = 0;
    //Logger::debug("BLOBNAME: "+blobName);
    //Logger::debug("EXTRPATH: "+extractionPath.string());
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

                bool extracted = false;
                if(result.isValid)
                {
                    //printResult(result, currentDepth);  // 👈 Print parent first
                    
                    if (enableExtraction && recursionDepth > 0) {
                        for (auto& extractor : extractors){
                            if(result.extractorType.compare(extractor->name()) == 0 )
                            {
                                Logger::debug("Using "+extractor->name()+" extractor with path: "+extractionPath.string());
                                Logger::debug(to_hex(offset) + " " + filePath.filename().string());
                                if(extractor->name() == "RAW")
                                {
                                    extractor->extract(blob, offset, extractionPath,result.type);
                                }
                                else
                                {
                                    extractor->extract(blob, offset, extractionPath);
                                }
                                
                                extracted = true;

                                if(recursionDepth > 0)
                                {
                                    for (const auto& entry : std::filesystem::recursive_directory_iterator(extractionPath.string()+"/"+to_hex(offset))) {
                                            if (entry.is_regular_file()) {
                                                bool found = std::find(alreadyAnalyzed.begin(), alreadyAnalyzed.end(), entry.path().string()) != alreadyAnalyzed.end();
                                                if(found)
                                                    continue;
                                                else
                                                    alreadyAnalyzed.push_back(entry.path().string());
                                                Logger::debug("SCANREC: "+entry.path().string());

                                                Scanner scanner(true, recursionDepth - 1,currentDepth+1,entry.path().parent_path());
                                                scanner.alreadyAnalyzed = alreadyAnalyzed;
                                                std::vector<ScanResult> tmpRes = scanner.scan(entry.path());
                                                alreadyAnalyzed = scanner.alreadyAnalyzed;
                                                result.children.insert(result.children.end(),std::make_move_iterator(tmpRes.begin()),std::make_move_iterator(tmpRes.end()));
           

                                            }
                                        }

                                }
                                break;
                            }
                        }
                        
    
                    }
                    if(offset == 0 && result.length == blob.size() && extracted == false && !verbose)
                    {
                        Logger::debug("ignoring complete file");
                    }
                    else
                    {
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
