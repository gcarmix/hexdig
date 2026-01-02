// extractor_registry.hpp
#pragma once
#include "base_extractor.hpp"
#include <functional>
#include <vector>
#include <memory>

class ExtractorRegistry {
public:
    using Creator = std::function<std::unique_ptr<BaseExtractor>()>;

    static ExtractorRegistry& instance() {
        static ExtractorRegistry registry;
        return registry;
    }

    void registerExtractor(Creator creator) {
        creators.push_back(std::move(creator));
    }

    std::vector<std::unique_ptr<BaseExtractor>> createAll() const {
        std::vector<std::unique_ptr<BaseExtractor>> result;
        for (const auto& creator : creators) {
            result.push_back(creator());
        }
        return result;
    }

private:
    std::vector<Creator> creators;
};
