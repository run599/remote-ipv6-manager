#pragma once
#include "PluginInterface.h"
#include <vector>
#include <string>
#include <map>
#include <functional>

// ═══════════════════════════════════════════════
// MCP 进程插件加载器
// 扫描 plugins/ 目录下的 plugin.json
// 按需启动独立进程，通过 stdin/stdout 管道通信
// 杀毒软件只看到一个干净的网络客户端
// ═══════════════════════════════════════════════

class PluginLoader {
public:
    // 设置嵌入式 Python 路径（宽字符，支持中文用户名）
    void setPythonPath(const std::wstring& pythonPath) { _pythonPathW = pythonPath; }

    // 扫描插件目录，读取所有 plugin.json
    void scanPlugins(const std::wstring& pluginDir);

    // 启动指定插件进程
    bool startPlugin(const std::string& pluginId);

    // 停止指定插件
    void stopPlugin(const std::string& pluginId);

    // 停止所有插件
    void stopAll();

    // 向插件发送命令并读取响应（阻塞）
    std::string callPlugin(const std::string& pluginId, const std::string& method, const std::string& params, int timeoutMs = 30000);

    // 构建 工具名 → 插件ID 映射（启动时调用一次）
    void buildToolMap();

    // 根据工具名查找处理它的插件 ID（tools/call 用）
    std::string resolvePluginForTool(const std::string& toolName) const;

    // 获取所有可用插件列表
    const std::vector<PluginConfig>& getPlugins() const { return _configs; }

private:
    std::vector<PluginConfig> _configs;
    std::vector<PluginProcess> _processes;
    std::map<std::string, std::string> _toolToPlugin; // 工具名 → 插件ID
    std::wstring _pythonPathW;  // 嵌入式 Python 路径（宽字符）

    PluginProcess* findProcess(const std::string& pluginId);
    PluginProcess* startProcess(const PluginConfig& config);
    std::string readResponse(HANDLE hStdOut, int timeoutMs);
};
