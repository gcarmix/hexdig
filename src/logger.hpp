#pragma once
#include <iostream>
#include <string>

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
            std::cerr << "[DEBUG] " << msg << "\n";
        }
    }

    static void info(const std::string& msg) {
        if (level >= LogLevel::INFO) {
            std::cerr << "[INFO] " << msg << "\n";
        }
    }

    static void error(const std::string& msg) {
        if (level >= LogLevel::ERROR) {
            std::cerr << "[ERROR] " << msg << "\n";
        }
    }
};
