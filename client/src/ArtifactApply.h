// ═══════════════════════════════════════════════════════════════════════════
// ArtifactApply —— 工件"落地之后怎么应用"的分发器
//
// 为什么需要它：能投放 EXE 只解决一半问题。真实运维要投放的多是**配置类工件**
// （注册表、本地策略、证书、计划任务、服务、防火墙、hosts、secedit 安全策略…），
// 它们要的不是"文件放上去"，而是"应用它" —— 而且要**能回滚**。
//
// 三条硬要求（改这个文件前先读）：
//
//   1) **先备份，再动手**。每个 kind 都必须知道"改了什么、怎么还原"：
//      没有备份路径的 kind 一律拒绝应用 —— 不可逆的操作不能靠"小心"。
//
//   2) **结果必须自证**。每个动作都记 命令原文 / 退出码 / 判定，
//      失败要给原因。这个项目里"打印成功但不看返回码"已经坑过一次。
//
//   3) **可 dry-run**。dryRun=true 只校验输入与报告影响面，绝不改系统。
//      投放策略这种事，先看一眼要动哪些键是基本要求。
//
// 备份与清单落在 <ProgramData>\r6m-backup\<工件名>\<时间戳>\：
// ═══════════════════════════════════════════════════════════════════════════

#pragma once

#include <string>

namespace r6m {

class ArtifactApply {
public:
    // kind 取值见 KnownKinds()。成功返回 true；
    // 失败时 err 带原因（必须能自证，不能只说"应用失败"）。
    // txId 非空时：备份清单会记 tx=<id>，并把 (工件, 备份目录) 登记到事务索引，
    static bool Apply(const std::string& kind, const std::string& filePathUtf8,
                      const std::string& applyArgs, const std::string& artifactName,
                      const std::string& txId,
                      bool dryRun, std::string& err, std::string& detail);

    // 从最近一次备份回滚（读 manifest.txt 决定怎么还原）
    static bool Rollback(const std::string& artifactName, std::string& err, std::string& detail);

    // 按事务 id 回滚**该事务**涉及的全部备份（逆序，即最后应用的先还原）
    static bool RollbackTx(const std::string& txId, std::string& err, std::string& detail);

    static bool IsKnown(const std::string& kind);

    // 校验"现状是否仍与期望一致"（定期自愈用）。
    // 返回 0=一致 / 1=已偏离(需重做) / 2=无法校验（如实上报，不假装一致）。
    // 从不看"它现在还在不在"，所以配置被改掉后期望态永远发现不了。
    static int Verify(const std::string& kind, const std::string& filePathUtf8,
                      const std::string& applyArgs, const std::string& artifactName,
                      std::string& detail);
    static std::string KnownKinds();
};

} // namespace r6m
