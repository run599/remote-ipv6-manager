#pragma once
#include "PluginLoader.h"
#include <string>
#include <map>
#include <atomic>
#include <thread>
#include <windows.h>
#include <wininet.h>

// ═══════════════════════════════════════════════
// Stub 核心 —— 只做三件事：
//   1. 连接 RMM 服务端
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
    // 统一 HTTP：withCredentials=false 时不带任何密钥头（用于发凭据前的标识探测）
    bool httpRequest(const char* method, const std::string& path, const std::string& body,
                     bool withCredentials, std::string& response);
    bool httpPost(const std::string& path, const std::string& body, std::string& response);
    std::string httpGet(const std::string& path);
    bool httpDownload(const std::string& url, const std::wstring& savePath);
    // 投放 run=true 的工件前终止同名实例（否则文件被锁、替换必败；
    // 而改名兼容处理会造成双实例，对单实例工具是致命冲突）
    int  StopRunningImages(const std::wstring& exeName);
    bool ImageRunning(const std::wstring& exeName);
    // 发凭据之前先做一次无凭据探测并校验 TLS 标识；失败即拒绝发送密钥
    bool probeAndVerifyPin();
    // per-agent 密钥自启动配置（DPAPI，机器范围），否则服务端重启前的重注册会被拒
    bool loadPersistedAgentKey();
    void persistAgentKey(const std::string& key);
    bool hasBootstrapKey() const { return !_bootstrapKeyObf.empty(); }
    void rememberBootstrapKey();
    // 安全隔离恢复
    void clearFuse(const char* why);

    // 循环
    void pollLoop();
    void heartbeatLoop();

    // ── 外置工件（投放时签发密钥并登记）──
    // 返回签发的 key（失败返回空串）。key 由受管端生成 —— 它才是唯一知道
    // 文件实际落在哪、以什么进程跑起来的一方。
    std::string issueArtifactKey(const std::string& targetDir, const std::string& fileName);

    // 工件"落地后应用"与回滚（注册表/策略/脚本/证书/任务/服务/hosts/防火墙…）
    bool handleRollbackFile(const std::string& params);

    // ── 断线可达性：候选端点 + 失败轮换 ──
    // in i.ini/env 里可以给多个地址（servers=a,b,c）。单端点是本项目的先天弱点：
    // IPv6 前缀一换就全体失联，而 agent 手上没有第二条路。
    std::vector<std::string> _servers;
    int  _serverIdx = 0;
    int  _epFails = 0;          // 当前端点连续失败次数
    void RebuildEndpointList();
    bool RotateEndpoint(const char* why);

    // ── 状态上报（admin/端点/失败数）──
    void ReportAgentStatus();
    bool _isAdmin = false;

    // ── 声明期望态：按期望收敛 ──
    // 传 JSON 文本而不是 r6m::Json：本头文件不包含 Json.h，
    // 直接用那个类型会报 "r6m 不是类或命名空间"。
    void DesiredTick(const std::string& pollRespJson);
    void ConvergeDesired(const std::string& desiredJson);
    std::wstring LedgerPath();
    std::string  _desiredRev;       // 本地已达成/记录到的 rev
    std::vector<std::string> _desiredFailed;   // 上次收敛的失败项（上报给历史）

    // ── 定期自愈：配置被人改掉后自动发现并恢复 ──
    // 原实现只比 rev（服务端改过没有），并以台账"记过没有"判达成 —— 台账只记
    // "我装过"，从不验证"它现在还在不在"，所以手动改掉的配置永远不恢复。
    bool _selfHeal = true;            // selfheal=1（默认开）
    int  _checkIntervalSec = 60;      // check_interval=60
    int  _healMaxPerWindow = 3;       // heal_max=3（每项每小时）
    unsigned long long _lastHealMs = 0;
    std::vector<std::string> _desiredDrift;      // 本轮检测到的偏离（上报）
    std::vector<std::string> _verifyUnsupported; // 无法校验的项（如实上报）
    std::map<std::string, int> _healCount;                 // 项  本轮窗口内已重做次数
    std::map<std::string, unsigned long long> _healWindow; // 项  窗口起点
    void SelfHealTick();
    void LoadHealConfig();
    int          _pollsSinceDesired = 0;
    // 事务化批量投放：全成或全回滚
    bool handleDeployBatch(const std::string& params);
    bool handleRollbackTx(const std::string& params);
    std::string _lastBatchReport;   // 事务的逐步报告（JSON 字符串）
    std::string _lastApplyDetail;   // 成功时的动作摘要（回给管理端，便于留痕）
    std::string _lastApplyErr;      // 失败原因（必须自证）
    std::string _lastDeployErr;     // 部署阶段失败原因
    std::string _lastArtifactKey;   // 供 deploy 结果回带给管理端

    // ── 屏幕监控（实时看屏）──
    void applyScreenStream(bool enabled, int scale, int intervalMs);
    void screenLoop();          // 采集线程主体
    void stopScreenStream();

    // 信息采集
    std::string collectSystemInfo();
    std::string generateHWID();

    // 部署
    bool handleDeployFile(const std::string& params);   // 返回真实成败，供 deploy_file 回传

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
    // 防的是被动刮取（内存转储/扫描）；定点 hook 由 IntegrityCheck 负责。
    std::string _agentKeyObf;   // key XOR mask 后的密文形态
    std::string _keyMask;       // 与 key 等长的随机掩码
    std::string _bootstrapKeyObf; // 引导密钥（仅用于首次登记 / 密钥失效后回退）
    std::string _bootstrapKeyMask;
    int _consecutiveOkChecks = 0; // 连续完整性自检正常次数，用于自动恢复
    // 旧成员 _agentKey 已移除；如需判断密钥是否已配置用 hasAgentKey()
    PluginLoader _plugins;
    std::atomic<bool> _running{false};
    std::atomic<bool> _integrityCompromised{false}; // IntegrityCheck 安全隔离：关键 API 被篡改时暂停指令执行
    std::thread _heartbeatThread;
    HINTERNET _hSession = nullptr;

    std::thread _screenThread;
    std::atomic<bool> _screenStop{false};
    std::atomic<bool> _screenActive{false};
    std::atomic<int>  _screenScale{4};
    std::atomic<int>  _screenInterval{400};
};
