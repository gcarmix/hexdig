#pragma once
#include <iostream>
#include <string>

namespace ansi {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string cyan    = "\033[36m";
    const std::string red     = "\033[31m";
    const std::string yellow  = "\033[33m";
    const std::string green   = "\033[32m";
    const std::string white = "\033[37m";
    const std::string gray    = "\033[90m";
}
enum class LogLevel {
    NONE,
    ERROR,
    INFO,
    DEBUG
};

class Logger {
public:
    static LogLevel level;

    static void setLevel(LogLevel newLevel) {
        level = newLevel;
    }

    static void debug(const std::string& msg) {
        if (level >= LogLevel::DEBUG) {
            std::cerr << ansi::gray << "[DEBUG] " << msg << "\n";
        }
    }

    static void info(const std::string& msg) {
        if (level >= LogLevel::INFO) {
            std::cerr << ansi::white << "[INFO] " << msg << "\n";
        }
    }

    static void error(const std::string& msg) {
        if (level >= LogLevel::ERROR) {
            std::cerr << ansi::red <<"[ERROR] " << msg << "\n";
        }
    }
};
