#pragma once
// ============================================================================
// IntegrityCheck.h —— 兼容 shim（2026-10-16 由 DSH 生成）
// 背景：本次上游仓库缺少本头文件，而 AntiHook.cpp 与 StubCore.cpp 都 #include 它。
//       经全文检索确认：IntegrityCheck 的实现位于 AntiHook.cpp，
//       其类声明与 IntegrityCheckState 枚举已经在 AntiHook.h 中给出。
//       因此本文件只做转发，**不引入任何新行为**（避免与既有实现冲突）。
// 若上游后续补回了真正的 IntegrityCheck.h，请直接删除本文件即可。
// ============================================================================
#include "AntiHook.h"