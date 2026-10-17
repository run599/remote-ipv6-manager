// ============================================================================
// IntegrityCheck.cpp  -  compatibility translation unit
// Generated 2026-10-16 by DSH.
// Why: upstream repo's client/CMakeLists.txt lists src/IntegrityCheck.cpp, but the
//      file is absent from the repository. The actual IntegrityCheck implementation
//      lives in AntiHook.cpp (GetDiskExportOffset / VerifyExportBytes /
//      CheckCriticalApis / LogReports / IsCompromised / SummaryForHeartbeat /
//      HasTampered / HasUnverifiable), and its declarations are in AntiHook.h.
//      This TU therefore only includes the header so that the build target has a
//      valid source file. It adds NO behavior and NO duplicate symbols.
// If upstream later restores the real file, simply delete this one.
// ============================================================================
#include "IntegrityCheck.h"
