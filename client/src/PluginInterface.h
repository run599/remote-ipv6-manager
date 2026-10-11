#pragma once
#include <string>
#include <windows.h>

// ═══════════════════════════════════════════════
// 插件接口 v2 — MCP 进程模式
// 插件不是 DLL，而是独立的命令行进程
// Stub 通过 stdio 管道与插件通信（MCP JSON-RPC 2.0，一行一个消息）
// ═══════════════════════════════════════════════

// 插件配置（plugin.json 解析后）
struct PluginConfig {
    std::string id;           // 插件 ID
    std::string name;         // 显示名称
    std::string version;      // 版本号
    std::string command;      // 启动命令: "python plugin.py"
    std::string workDir;      // 工作目录
    std::string description;  // 描述
};

// 插件进程句柄
struct PluginProcess {
    PluginConfig config;
    HANDLE hProcess = nullptr;
    HANDLE hStdIn = nullptr;   // 写入到插件 stdin
    HANDLE hStdOut = nullptr;  // 从插件 stdout 读取
    HANDLE hStdErr = nullptr;  // 必须有人排空，否则插件写满管道会永久阻塞
    bool running = false;
    // 行分帧缓冲：ReadFile 可能一次读到多条消息，剩下的留到这里
    std::string rxbuf;
};
