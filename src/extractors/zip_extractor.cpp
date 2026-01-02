#include "scanner.hpp"
#include "base_extractor.hpp"
#include "extractor_registration.hpp"
#include <zip.h>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <iostream>
#include "helpers.hpp"

namespace fs = std::filesystem;

class ZIPExtractor : public BaseExtractor {
public:
std::string name() const override { return "ZIP"; };
void extract(const std::vector<uint8_t>& blob,
                                              size_t offset,
                                              fs::path extractionPath) {


    extractionPath = extractionPath /fs::path(to_hex(offset)); 

    fs::create_directories(extractionPath);


    zip_error_t error;
    zip_error_init(&error);

    zip_source_t* src = zip_source_buffer_create(blob.data() + offset, blob.size() - offset, 0, &error);
    if (!src) {
        std::cerr << "ZIPExtractor: Failed to create zip source: " << zip_error_strerror(&error) << "\n";
        zip_error_fini(&error);
        return;
    }

    zip_t* archive = zip_open_from_source(src, 0, &error);
    if (!archive) {
        std::cerr << "ZIPExtractor: Failed to open zip archive: " << zip_error_strerror(&error) << "\n";
        zip_source_free(src);
        zip_error_fini(&error);
        return ;
    }

    zip_int64_t num_entries = zip_get_num_entries(archive, 0);
    for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(num_entries); ++i) {
        struct zip_stat st;
        if (zip_stat_index(archive, i, 0, &st) != 0 || st.size == 0) {
            continue;
        }

        zip_file_t* zf = zip_fopen_index(archive, i, 0);
        if (!zf) continue;

        std::vector<uint8_t> fileData(st.size);
        zip_fread(zf, fileData.data(), st.size);
        zip_fclose(zf);

        // Write to extractions/ folder
        fs::path outputPath = extractionPath / fs::path(st.name).filename();
std::ofstream outFile(outputPath, std::ios::binary);
if (outFile.is_open()) {
    outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    outFile.close();
}

    }

    zip_close(archive);
    zip_error_fini(&error);
    return ;
}

};

REGISTER_EXTRACTOR(ZIPExtractor)