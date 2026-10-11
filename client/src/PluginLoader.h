#pragma once
#include "PluginInterface.h"
#include <vector>
#include <list>
#include <string>
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>

// ═══════════════════════════════════════════════
// MCP 进程插件加载器
// 扫描 plugins/ 目录下的 plugin.json
// 按需启动独立进程，通过 stdin/stdout 管道通信
// ═══════════════════════════════════════════════

class PluginLoader {
public:
    // 设置嵌入式 Python 路径（宽字符，支持中文用户名）
    void setPythonPath(const std::wstring& pythonPath) { _pythonPathW = pythonPath; }

    // 扫描插件目录，读取所有 plugin.json
    void scanPlugins(const std::wstring& pluginDir);

    // 启动指定插件进程
    bool startPlugin(const std::string& pluginId);

    // 停止指定插件（先发 JSON-RPC shutdown，超时才强杀）
    void stopPlugin(const std::string& pluginId);

    // 停止所有插件
    void stopAll();

    // 向插件发送命令并读取响应（阻塞，按 JSON-RPC id 匹配应答）
    std::string callPlugin(const std::string& pluginId, const std::string& method,
                           const std::string& params, int timeoutMs = 30000);

    std::string listAllTools();

    void buildToolMap();

    // 根据工具名查找处理它的插件 ID（tools/call 用）
    std::string resolvePluginForTool(const std::string& toolName) const;

    // 获取所有可用插件列表
    const std::vector<PluginConfig>& getPlugins() const { return _configs; }
    // 上一次成功扫描的结果：供"本次扫到 0 个"时回退，
    // 避免一次误扫（目录传错 / 尚未就绪）把工具映射打成空的。
    std::vector<PluginConfig> saved;

private:
    std::vector<PluginConfig> _configs;
    // list 而非 vector：callPlugin 持有 PluginProcess* 期间其他插件 startPlugin
    // 会触发 vector 扩容导致指针悬垂
    std::list<PluginProcess> _processes;
    std::map<std::string, std::string> _toolToPlugin; // 工具名  插件ID
    std::wstring _pythonPathW;  // 嵌入式 Python 路径（宽字符）
    int _nextId = 1;            // JSON-RPC 请求 id（必须自增且与应答配对）

    // callPlugin 串行化锁。
    // stdin/stdout 管道。两个线程交错写会把 JSON-RPC 帧搅在一起，
    // 再加 id 自增就会"应答配错请求"，症状是偶发拿到别的工具的返回值。
    mutable std::mutex _callMutex;

    // stderr 排空线程：插件往 stderr 写日志是常态，没人读就会写满管道而卡死
    std::map<std::string, std::thread> _errThreads;
    std::map<std::string, std::shared_ptr<std::atomic<bool>>> _errStop;

    PluginProcess* findProcess(const std::string& pluginId);
    PluginProcess* startProcess(const PluginConfig& config);
    void startErrDrain(const std::string& pluginId, HANDLE hErr);
    void stopErrDrain(const std::string& pluginId);
    // 读一行（以 \n 结束）；剩余字节留在 proc.rxbuf。返回空串表示超时或管道关闭
    std::string readLine(PluginProcess* proc, int timeoutMs);
};
