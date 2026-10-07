#pragma once
#include <string>
#include <vector>
#include <atomic>

// ═══════════════════════════════════════════════
// AntiHook — 进程完整性自检（三段式：检测 / 上报 / 熔断）
//
// 检测：比对关键 API 入口在内存中的字节与磁盘上原始
//       DLL 的导出函数字节，不一致通常意味着 inline hook。
// 上报：结果随心跳发送服务端，服务端将该 agent 标记为
//       integrity-compromised。
// 熔断：检测到关键 API 被篡改时，由调用方暂停 poll 循环，
//       不再执行新指令，直到人工确认恢复。
//
// 设计边界（有意为之，不接受更改）：
//   - 不恢复（unhook）被篡改的代码
//   - 不使用直接系统调用绕过
//   - 不对端点安全产品隐藏行为
// 目的：发现恶意代码注入，供运维排查。
// ═══════════════════════════════════════════════

struct ApiIntegrityReport {
    std::string function;   // e.g. "EncryptMessage"
    std::string module;     // 实际拥有该函数的模块名
    bool intact;            // 是否逐字节一致
    std::string detail;     // 差异描述或失败原因
    // 三态：0=一致 1=确认被改（tampered） 2=无法验证（unverifiable）
    // 关键区分：模块没加载 / 转发导出 / 权限不足 都属"无法验证"，
    // 原实现把它们与"被篡改"混为一谈，会让 agent 永久熔断且无恢复通道。
    int state;
};

enum AntiHookState { AH_INTACT = 0, AH_TAMPERED = 1, AH_UNVERIFIABLE = 2 };

class AntiHook {
public:
    // 校验所有关键 API
    // 返回 false 表示发现篡改（或无法验证），此时应触发熔断
    static bool CheckCriticalApis(std::vector<ApiIntegrityReport>& reports);

    // 将结果写入本地日志
    static void LogReports(const std::vector<ApiIntegrityReport>& reports);

    // 关键 API 是否被篡改（用于熔断判断；未验证也视为不可信）
    static bool IsCompromised();
    // 是否存在"确认被篡改"的函数
    static bool HasTampered(const std::vector<ApiIntegrityReport>& reports);
    // 是否存在"无法验证"的函数
    static bool HasUnverifiable(const std::vector<ApiIntegrityReport>& reports);

    // 上报用摘要："ok" 或 "tampered:EncryptMessage,ReadFile"
    static std::string SummaryForHeartbeat();

private:
    // 单个函数的字节比对
    static bool VerifyExportBytes(const char* funcName, const char* dllName,
                                  ApiIntegrityReport& report);
    // 解析磁盘 PE 的导出表，返回函数在磁盘文件中的偏移与 RVA
    static bool GetDiskExportOffset(const std::wstring& dllPath, const char* funcName,
                                    unsigned long& fileOffset, unsigned long& rva);
};
