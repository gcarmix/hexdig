// parser_registration.hpp
#pragma once
#include "parser_registry.hpp"

#define REGISTER_PARSER(CLASSNAME) \
    namespace { \
        struct CLASSNAME##_AutoRegister { \
            CLASSNAME##_AutoRegister() { \
                ParserRegistry::instance().registerParser([]() { \
                    return std::make_unique<CLASSNAME>(); \
                }); \
            } \
        }; \
        static CLASSNAME##_AutoRegister global_##CLASSNAME##_AutoRegister; \
    }
