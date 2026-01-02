// parser_registry.hpp
#pragma once
#include "base_parser.hpp"
#include <functional>
#include <vector>
#include <memory>

class ParserRegistry {
public:
    using Creator = std::function<std::unique_ptr<BaseParser>()>;

    static ParserRegistry& instance() {
        static ParserRegistry registry;
        return registry;
    }

    void registerParser(Creator creator) {
        creators.push_back(std::move(creator));
    }

    std::vector<std::unique_ptr<BaseParser>> createAll() const {
        std::vector<std::unique_ptr<BaseParser>> result;
        for (const auto& creator : creators) {
            result.push_back(creator());
        }
        return result;
    }

private:
    std::vector<Creator> creators;
};
