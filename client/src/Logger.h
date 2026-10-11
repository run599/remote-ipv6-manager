#pragma once
// ═══════════════════════════════════════════════════════════════════════════
// Logger —— 可选落盘的诊断日志
//
// 兼容性适配约束（改动前务必读）：
//   ① 本地明文日志是内存兼容性适配的天敌：client.log 里写着服务端地址、指令名、
//      插件路径，是取证最直接的入口。因此 **兼容性适配开启时默认不落盘**，
//      只走 OutputDebugString（无调试器时等于丢弃）。
//   ② 需要日志时由 Compat 生成随机路径（%LOCALAPPDATA%\<随机>\<随机>.tmp），
//   ③ 退出时由 CleanupArtifacts() 用随机噪声覆盖后再删除。
// ═══════════════════════════════════════════════════════════════════════════

#include <windows.h>
// 混淆字面量（R6M_STR_*）：本头文件只用到窄串，故仅需 XorCore + 表
#include "XorCore.h"
#include "generated_strings.h"
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <cstdio>

// 兼容层钩子（实现在 Compat.cpp）—— 必须在 Logger 类之前声明，
// 类内联成员函数里要调用它们。
bool r6m_ev_disk_log_enabled();
std::wstring r6m_ev_log_path();

class Logger {
public:
    enum Level { L_DEBUG = 0, L_INFO = 1, L_WARN = 2, L_ERROR = 3 };

    static Logger& instance() { static Logger i; return i; }

    // preferredPath 仅在"允许落盘"时被忽略（改用 Compat 的随机路径）。
    // 允许落盘时会把实际使用的路径记到 actualPath()，供退出清理使用。
    void init(const wchar_t* preferredPath) {
        std::lock_guard<std::mutex> lock(mtx);
        if (_inited) return;
        _inited = true;
        if (r6m_ev_disk_log_enabled()) {
            _path = r6m_ev_log_path();
            if (_path.empty() && preferredPath) _path = preferredPath;
            if (!_path.empty()) file.open(_path, std::ios::app);
            _onDisk = file.is_open();
        } else {
            _onDisk = false;   // 兼容性适配模式：不落盘，只走调试输出
        }
    }

    bool onDisk() const { return _onDisk; }
    const std::wstring& path() const { return _path; }

    void log(Level level, const char* comp, const char* msg) {
        if (!_onDisk) {
            // 无落盘：只发调试输出（无调试器时是空操作），不留磁盘痕迹
            if (comp && msg) {
                std::string line = std::string(R6M_STR_DB1F112A465F1E40) + comp + "|" + msg + "\n";
                OutputDebugStringA(line.c_str());
            }
            return;
        }
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        struct tm tb;
        localtime_s(&tb, &t);
        char ts[64];
        snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
                 tb.tm_year + 1900, tb.tm_mon + 1, tb.tm_mday,
                 tb.tm_hour, tb.tm_min, tb.tm_sec, (int)ms.count());
        const char* lv[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };
        std::string line = std::string(ts) + " [" + lv[level] + "] [" + comp + "] " + msg;
        if (file.is_open()) { file << line << "\n"; file.flush(); }
        OutputDebugStringA((line + "\n").c_str());
    }

private:
    std::ofstream file;
    std::wstring  _path;
    std::mutex    mtx;
    bool          _onDisk = false;
    bool          _inited = false;
};

// 兼容层钩子已在文件顶部声明（Compat.cpp 实现），此处不再重复。

#define LOG_D(c, m) Logger::instance().log(Logger::L_DEBUG, c, m)
#define LOG_DEBUG(c, m) Logger::instance().log(Logger::L_DEBUG, c, m)
#define LOG_I(c, m) Logger::instance().log(Logger::L_INFO, c, m)
#define LOG_INFO(c, m) Logger::instance().log(Logger::L_INFO, c, m)
#define LOG_W(c, m) Logger::instance().log(Logger::L_WARN, c, m)
#define LOG_WARN(c, m) Logger::instance().log(Logger::L_WARN, c, m)
#define LOG_E(c, m) Logger::instance().log(Logger::L_ERROR, c, m)
#define LOG_ERROR(c, m) Logger::instance().log(Logger::L_ERROR, c, m)
