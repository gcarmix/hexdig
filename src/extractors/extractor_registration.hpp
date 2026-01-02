// extractor_registration.hpp
#pragma once
#include "extractor_registry.hpp"

#define REGISTER_EXTRACTOR(CLASSNAME) \
    namespace { \
        struct CLASSNAME##_AutoRegister { \
            CLASSNAME##_AutoRegister() { \
                ExtractorRegistry::instance().registerExtractor([]() { \
                    return std::make_unique<CLASSNAME>(); \
                }); \
            } \
        }; \
        static CLASSNAME##_AutoRegister global_##CLASSNAME##_AutoRegister; \
    }
