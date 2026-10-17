#include "IntegrityCheck.h"
#include <windows.h>
#include <psapi.h>
#include "Logger.h"
#include "Compat.h"
#include <string>
#include <vector>
#include <fstream>
#include <cstddef> // offsetof

#pragma comment(lib, "psapi.lib")

// ═══════════════════════════════════════════════
// IntegrityCheck 实现 — 内存 vs 磁盘字节比对
//
// 关键 API 清单：覆盖 TLS 加密入口、文件读取、进程创建、
// 管道读写。这些是恶意软件最常挂钩的咽喉点。
// ═══════════════════════════════════════════════

// 关键 API 清单。注意：名字用混淆常量（R6M_STR_*）表达，它们是**运行期
// 解码函数**而不是编译期字面量，所以不能写成 static 数组初始化器（那会
// 触发动态初始化，且 C++ 不允许用函数调用初始化 const char* 的静态数组）。
// 改为进程内一次性惰性构建。
//
//    R6M_STR_* 展开成 Decode()，而 Decode() 返回的是其内部缓冲区的地址；
//    这张表是**长期持有**的，于是表建好之后程序里任何一次 Decode()
//    都会覆盖那块内存，表里的名字就变成了"最后一次解码的那个字符串"。
//    实测症状：完整性报告里冒出 HTTP@clear_integrity、request_id@X-Agent-HWID
//    （都是服务端 HTTP 字段的名字，报 `module not loaded`），
//    而真正的关键 API 名字时对时错 —— 排查时极难联想到"表被覆盖"。
//    改成 std::string 后赋值即拷贝，彻底断掉这层别名。
struct CriticalApi { std::string func; std::string dll; };
static const CriticalApi* CriticalApis(size_t& count) {
    static CriticalApi tbl[8];
    static size_t n = 0;
    if (n == 0) {
        tbl[0] = { R6M_STR_263D7A4A24997D69, R6M_STR_4298DC2D09F85768 };
        tbl[1] = { R6M_STR_4DAA853C34665041, R6M_STR_4298DC2D09F85768 };
        tbl[2] = { R6M_STR_6F4E79C87F04F3E6, R6M_STR_32EACF116EB05411 };  // InternetReadFile@wininet.dll
        tbl[3] = { R6M_STR_76B6FA9B2B832D63, R6M_STR_32EACF116EB05411 };  // HttpSendRequestA@wininet.dll
        tbl[4] = { R6M_STR_2E97865AB85128C3, R6M_STR_E14B18A7ACF9C443 };
        tbl[5] = { R6M_STR_2FA16C1D95E4306A, R6M_STR_E14B18A7ACF9C443 };
        tbl[6] = { R6M_STR_9C756D1C853AD7BF, R6M_STR_E14B18A7ACF9C443 };
        tbl[7] = { R6M_STR_EBC4DAE9B1541624, R6M_STR_E14B18A7ACF9C443 };
        n = 8;
    }
    count = n;
    return tbl;
}

// 比对的入口字节数：inline hook 通常在函数头部 ~16 字节内打补丁
static const unsigned long kCompareBytes = 16;

static std::wstring GetModulePath(HMODULE hMod) {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(hMod, path, MAX_PATH);
    return path;
}

// 在磁盘 PE 文件中定位导出函数的文件偏移与 RVA
bool IntegrityCheck::GetDiskExportOffset(const std::wstring& dllPath, const char* funcName,
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

bool IntegrityCheck::VerifyExportBytes(const char* funcName, const char* dllName,
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

    // 走到这里才是真的字节不一致 —— 唯一应触发安全隔离的情况
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

bool IntegrityCheck::CheckCriticalApis(std::vector<ApiIntegrityReport>& reports) {
    reports.clear();
    bool allOk = true;
    size_t apiCount = 0;
    const CriticalApi* apis = CriticalApis(apiCount);
    for (size_t ai = 0; ai < apiCount; ai++) {
        const auto& api = apis[ai];
        ApiIntegrityReport r;
        if (!VerifyExportBytes(api.func.c_str(), api.dll.c_str(), r)) allOk = false;
        reports.push_back(r);
    }
    return allOk;
}

void IntegrityCheck::LogReports(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.intact) {
            LOG_D(R6M_STR_A75CB382EA5851B2, (r.function + "@" + r.module + ": intact").c_str());
        } else {
            LOG_E(R6M_STR_A75CB382EA5851B2, (r.function + "@" + r.module + ": " + r.detail).c_str());
        }
    }
}

bool IntegrityCheck::IsCompromised() {
    std::vector<ApiIntegrityReport> reports;
    bool ok = CheckCriticalApis(reports);
    LogReports(reports);
    return !ok;
}

std::string IntegrityCheck::SummaryForHeartbeat() {
    std::vector<ApiIntegrityReport> reports;
    bool ok = CheckCriticalApis(reports);
    LogReports(reports);
    if (ok) return "ok";

    // 分开上报：只有"确认被篡改"才让服务端标红，避免把"没加载的模块"
    // 报成被集成（原来一律 tampered:，会误导运维去排查不存在的集成）
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

bool IntegrityCheck::HasTampered(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.state == AH_TAMPERED) return true;
    }
    return false;
}

bool IntegrityCheck::HasUnverifiable(const std::vector<ApiIntegrityReport>& reports) {
    for (const auto& r : reports) {
        if (r.state == AH_UNVERIFIABLE) return true;
    }
    return false;
}
