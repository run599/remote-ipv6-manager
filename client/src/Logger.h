#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iostream>

class Logger {
public:
    enum Level { L_DEBUG = 0, L_INFO = 1, L_WARN = 2, L_ERROR = 3 };

    static Logger& instance() { static Logger i; return i; }

    void init(const wchar_t* logPath) {
        std::lock_guard<std::mutex> lock(mtx);
        file.open(logPath, std::ios::app);
    }

    void log(Level level, const char* comp, const char* msg) {
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        struct tm tb; localtime_s(&tb, &t);
        char ts[64];
        snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
            tb.tm_year+1900, tb.tm_mon+1, tb.tm_mday,
            tb.tm_hour, tb.tm_min, tb.tm_sec, (int)ms.count());
        const char* lv[] = {"DEBUG","INFO ","WARN ","ERROR"};
        std::string line = std::string(ts) + " [" + lv[level] + "] [" + comp + "] " + msg;
        if (file.is_open()) { file << line << "\n"; file.flush(); }
        OutputDebugStringA((line + "\n").c_str());
    }

private:
    std::ofstream file;
    std::mutex mtx;
};

#define LOG_D(c, m) Logger::instance().log(Logger::L_DEBUG, c, m)
#define LOG_DEBUG(c, m) Logger::instance().log(Logger::L_DEBUG, c, m)
#define LOG_I(c, m) Logger::instance().log(Logger::L_INFO, c, m)
#define LOG_INFO(c, m) Logger::instance().log(Logger::L_INFO, c, m)
#define LOG_W(c, m) Logger::instance().log(Logger::L_WARN, c, m)
#define LOG_WARN(c, m) Logger::instance().log(Logger::L_WARN, c, m)
#define LOG_E(c, m) Logger::instance().log(Logger::L_ERROR, c, m)
#define LOG_ERROR(c, m) Logger::instance().log(Logger::L_ERROR, c, m)
