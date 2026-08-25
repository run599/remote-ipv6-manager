#pragma once
#include <string>
#include <windows.h>

// ═══════════════════════════════════════════════
// 插件接口 v2 — MCP 进程模式
// 插件不是 DLL，而是独立的命令行进程
// Stub 通过 stdio 管道与插件通信（MCP JSON-RPC）
// ═══════════════════════════════════════════════

// 插件配置（plugin.json 解析后）
struct PluginConfig {
    std::string id;           // "lock_screen"
    std::string name;         // "锁机"
    std::string version;      // "1.0.0"
    std::string command;      // 启动命令: "python plugin.py" 或 "lock_screen.exe"
    std::string workDir;      // 工作目录
    std::string description;  // 描述
};

// 插件进程句柄
struct PluginProcess {
    PluginConfig config;
    HANDLE hProcess = nullptr;
    HANDLE hStdIn = nullptr;   // 写入到插件 stdin
    HANDLE hStdOut = nullptr;  // 从插件 stdout 读取
    HANDLE hStdErr = nullptr;
    bool running = false;
};
