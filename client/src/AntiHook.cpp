#include "AntiHook.h"
#include <windows.h>
#include <psapi.h>
#include "Logger.h"
#include <string>
#include <vector>
#include <fstream>
#include <cstddef> // offsetof

#pragma comment(lib, "psapi.lib")

// ═══════════════════════════════════════════════
// AntiHook 实现 — 内存 vs 磁盘字节比对
//
// 关键 API 清单：覆盖 TLS 加密入口、文件读取、进程创建、
// 管道读写。这些是恶意软件最常挂钩的咽喉点。
// ═══════════════════════════════════════════════

static const struct { const char* func; const char* dll; } kCriticalApis[] = {
    { "EncryptMessage",   "sspicli.dll"  },  // TLS 加密前明文必经（WinInet 经 sspicli 转发）
    { "DecryptMessage",   "sspicli.dll"  },
    { "InternetReadFile", "wininet.dll"  },  // 响应明文
    { "HttpSendRequestA", "wininet.dll"  },  // 请求明文（含 X-Agent-Key）
    { "ReadFile",         "kernel32.dll" },
    { "WriteFile",        "kernel32.dll" },
    { "CreateProcessW",   "kernel32.dll" },
    { "CreateFileW",      "kernel32.dll" },
};

// 比对的入口字节数：inline hook 通常在函数头部 ~16 字节内打补丁
static const unsigned long kCompareBytes = 16;

static std::wstring GetModulePath(HMODULE hMod) {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(hMod, path, MAX_PATH);
    return path;
}

// 在磁盘 PE 文件中定位导出函数的文件偏移与 RVA
bool AntiHook::GetDiskExportOffset(const std::wstring& dllPath, const char* funcName,
                                   unsigned long& fileOffset, unsigned long& rva) {
    std::ifstream f(dllPath, std::ios::binary);
    if (!f) return false;

    // 读 DOS 头
    IMAGE_DOS_HEADER dos = {};
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!f || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

    // 读 NT 头：签名(4) + 文件头(20)
    DWORD signature = 0;
    f.seekg(dos.e_lfanew);
    f.read(reinterpret_cast<char*>(&signature), 4);
    if (!f || signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_FILE_HEADER fileHdr = {};
    f.read(reinterpret_cast<char*>(&fileHdr), sizeof(fileHdr));
    if (!f) return false;

    // 读 OptionalHeader.Magic（2 字节）——决定 32/64 位布局
    WORD magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 2);
    if (!f) return false;
    bool isPE32Plus = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // DataDirectory 在 OptionalHeader 内的偏移：PE32+ = 112，PE32 = 96
    const unsigned long optHeaderStart = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    const unsigned long dataDirOffset = optHeaderStart + (isPE32Plus ? 112 : 96);

    unsigned long expDirRva = 0, expDirSize = 0;
    {
        IMAGE_DATA_DIRECTORY dirs[16] = {};
        f.seekg(dataDirOffset);
        f.read(reinterpret_cast<char*>(dirs), sizeof(dirs));
        if (!f) return false;
        expDirRva = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expDirSize = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    // 找导出目录
    if (expDirRva == 0 || expDirSize == 0) return false;

    // 读节表（跟在 NT 头之后，按实际位数计算大小）
    unsigned long ntHeaderSize = 4 + sizeof(IMAGE_FILE_HEADER) + (isPE32Plus ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
    f.seekg(dos.e_lfanew + ntHeaderSize);
    if (fileHdr.NumberOfSections == 0) return false;
    std::vector<IMAGE_SECTION_HEADER> sections(fileHdr.NumberOfSections);
    f.read(reinterpret_cast<char*>(sections.data()),
           fileHdr.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (!f) return false;

    auto rvaToOffset = [&](unsigned long r) -> unsigned long {
        for (const auto& s : sections) {
            if (r >= s.VirtualAddress && r < s.VirtualAddress + s.Misc.VirtualSize) {
                return s.PointerToRawData + (r - s.VirtualAddress);
            }
        }
        return 0;
    };

    // 读导出目录
    unsigned long expOff = rvaToOffset(expDirRva);
    if (expOff == 0) return false;
    IMAGE_EXPORT_DIRECTORY exp = {};
    f.seekg(expOff);
    f.read(reinterpret_cast<char*>(&exp), sizeof(exp));
    if (!f) return false;

    // 读名称表与序号表
    std::vector<unsigned long> names(exp.NumberOfNames);
    std::vector<unsigned short> ords(exp.NumberOfNames);
    if (exp.NumberOfNames == 0) return false;
    unsigned long namesOff = rvaToOffset(exp.AddressOfNames);
    unsigned long ordsOff = rvaToOffset(exp.AddressOfFunctions);
    unsigned long ordTableOff = rvaToOffset(exp.AddressOfNameOrdinals);
    if (!namesOff || !ordsOff || !ordTableOff) return false;

    f.seekg(namesOff);
    f.read(reinterpret_cast<char*>(names.data()), exp.NumberOfNames * 4);
    if (!f) return false;

    f.seekg(ordTableOff);
    f.read(reinterpret_cast<char*>(ords.data()), exp.NumberOfNames * 2);
    if (!f) return false;

    // 找目标函数
    for (unsigned long i = 0; i < exp.NumberOfNames; i++) {
        unsigned long nameRva = names[i];
        unsigned long nameOff = rvaToOffset(nameRva);
        if (!nameOff) continue;
        f.seekg(nameOff);
        std::string name;
        char c;
        while (f.get(c) && c != 0) name += c;
        if (name == funcName) {
            unsigned short ordIndex = ords[i];
            unsigned long funcRva = 0;
            f.seekg(ordsOff + ordIndex * 4);
            f.read(reinterpret_cast<char*>(&funcRva), 4);
            if (!f) return false;
            // 转发导出（指向别的 DLL）不比对
            if (funcRva >= expDirRva &&
                funcRva < expDirRva + expDirSize) {
                return false;
            }
            unsigned long off = rvaToOffset(funcRva);
            if (!off) return false;
            fileOffset = off;
            rva = funcRva;
            return true;
        }
    }
    return false;
}

bool AntiHook::VerifyExportBytes(const char* funcName, const char* dllName,
                                 ApiIntegrityReport& report) {
    report.function = funcName;
    report.intact = false;
    report.state = AH_UNVERIFIABLE;   // 默认"无法验证"，只有逐字节比对通过才置 AH_INTACT

    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) {
        report.module = dllName;
        report.detail = "module not loaded";
        return false;
    }

    FARPROC mem = GetProcAddress(hMod, funcName);
    if (!mem) {
        report.module = dllName;
        report.detail = "export not found";
        return false;
    }

    // 解析真实归属模块：dllName 可能只是转发方（如 sspicli 转发 EncryptMessage）
    HMODULE hOwner = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(mem), &hOwner) || !hOwner) {
        report.module = dllName;
        report.detail = "owner module not resolvable";
        return false;
    }

    // 模块显示名取路径末段
    std::wstring ownerPath = GetModulePath(hOwner);
    std::string ownerName;
    {
        size_t pos = ownerPath.find_last_of(L'\\');
        std::wstring wname = (pos == std::wstring::npos) ? ownerPath : ownerPath.substr(pos + 1);
        ownerName.assign(wname.begin(), wname.end());
    }
    report.module = ownerName;

    unsigned long fileOffset = 0, rva = 0;
    if (!GetDiskExportOffset(ownerPath, funcName, fileOffset, rva)) {
        report.detail = "disk export not resolvable (owner=" + ownerName + ")";
        return false;
    }

    // 从磁盘读原始入口字节
    std::ifstream f(ownerPath, std::ios::binary);
    if (!f) {
        report.detail = "cannot open disk image";
        return false;
    }
    unsigned char diskBytes[kCompareBytes] = {};
    f.seekg(fileOffset);
    f.read(reinterpret_cast<char*>(diskBytes), kCompareBytes);
    if (!f) {
        report.detail = "disk read short";
        return false;
    }

    // 读内存入口字节
    unsigned char memBytes[kCompareBytes] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), mem, memBytes, kCompareBytes, &read)
        || read != kCompareBytes) {
        report.detail = "memory read failed";
        return false;
    }

    if (memcmp(diskBytes, memBytes, kCompareBytes) == 0) {
        report.intact = true;
        report.state = AH_INTACT;
        report.detail = "ok";
        return true;
    }

    // 走到这里才是真的字节不一致 —— 唯一应触发熔断的情况
    report.state = AH_TAMPERED;

    // 差异描述：前若干字节的 hex 对比
    char diskHex[33], memHex[33];
    for (int i = 0; i < 8; i++) {
        snprintf(diskHex + i * 2, 3, "%02x", diskBytes[i]);
        snprintf(memHex + i * 2, 3, "%02x", memBytes[i]);
    }
    report.detail = std::string("hooked? disk=") + diskHex + " mem=" + memHex;
    return false;
}

bool AntiHook::CheckCriticalApis(std::vector<ApiIntegrityReport>& reports) {
    reports.clear();
    bool allOk = true;
    for (const auto& api : kCriticalApis) {
        ApiIntegrityReport r;
        if (!VerifyExportBytes(api.func, api.dll, r)) allOk = false;
        reports.push_back(r);
    }
    return allOk;
}

void AntiHook::LogReports(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.intact) {
            LOG_D("AntiHook", (r.function + "@" + r.module + ": intact").c_str());
        } else {
            LOG_E("AntiHook", (r.function + "@" + r.module + ": " + r.detail).c_str());
        }
    }
}

bool AntiHook::IsCompromised() {
    std::vector<ApiIntegrityReport> reports;
    bool ok = CheckCriticalApis(reports);
    LogReports(reports);
    return !ok;
}

std::string AntiHook::SummaryForHeartbeat() {
    std::vector<ApiIntegrityReport> reports;
    bool ok = CheckCriticalApis(reports);
    LogReports(reports);
    if (ok) return "ok";

    // 分开上报：只有"确认被篡改"才让服务端标红，避免把"没加载的模块"
    // 报成被注入（原来一律 tampered:，会误导运维去排查不存在的注入）
    std::string bad, unknown;
    for (const auto& r : reports) {
        if (r.state == AH_TAMPERED) {
            if (!bad.empty()) bad += ",";
            bad += r.function;
        } else if (r.state == AH_UNVERIFIABLE) {
            if (!unknown.empty()) unknown += ",";
            unknown += r.function;
        }
    }
    if (!bad.empty()) return "tampered:" + bad;
    return "unverifiable:" + unknown;
}

bool AntiHook::HasTampered(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.state == AH_TAMPERED) return true;
    }
    return false;
}

bool AntiHook::HasUnverifiable(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.state == AH_UNVERIFIABLE) return true;
    }
    return false;
}
