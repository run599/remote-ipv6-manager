#include "SelfGuard.h"
#include "Logger.h"

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <fstream>

// 日志标签：与 TaskLock 用同一个已混淆常量，避免新增字面量动混淆表
#define SG_TAG R6M_STR_D9CF61251F402ED5

namespace r6m {

namespace {

const wchar_t* kGuardFlag = L"--r6m-guard";
const wchar_t* kStopFlag  = L"--r6m-stop";   // 主进程优雅退出时给常驻的暗号

// ── 配置 ────────────────────────────────────────────────────────────────────
std::wstring SelfPath() {
    wchar_t p[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    return std::wstring(p);
}

std::wstring ExeDir() {
    std::wstring s = SelfPath();
    size_t k = s.find_last_of(L'\\');
    return (k == std::wstring::npos) ? std::wstring(L".") : s.substr(0, k);
}

//   · r6m.guard.pid：**只由常驻**写，供主进程判断"是不是已经有常驻在跑"
//   · r6m.main.pid ：**只由主进程**写，供常驻知道该盯谁
// 每个常驻各有各的复活计数，有界规则永远不触发 —— 管理员再也停不下来。
std::wstring StateDir() {
    static std::wstring cached;
    if (!cached.empty()) return cached;
    std::wstring a = ExeDir() + L"\\r6m.guard.pid";
    HANDLE h = CreateFileW(a.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        cached = ExeDir() + L"\\";
    } else {
        wchar_t tmp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tmp);
        cached = std::wstring(tmp);
    }
    return cached;
}

std::wstring GuardPidFile() { return StateDir() + L"r6m.guard.pid"; }
std::wstring MainPidFile()  { return StateDir() + L"r6m.main.pid"; }
std::wstring StopFile()     { return StateDir() + L"r6m.stop"; }


// 配置读取：环境变量优先（便于一次性试验），否则读 r6m.ini
std::string Opt(const char* envName, const wchar_t* iniKey, const char* defVal) {
    const char* e = getenv(envName);
    if (e && *e) return std::string(e);
    std::wstring wk(iniKey);
    std::string v;
    // 把宽字符 key 转成窄 ASCII（都是自定的 ASCII 键名）
    std::string narrow;
    for (wchar_t c : wk) { if (c < 128) narrow += (char)c; }
    // ReadIni 内部按窄键名匹配
    {
        // 直接读文件、按窄键名匹配
        std::wstring path = ExeDir() + L"\\r6m.ini";
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::string(defVal);
        char buf[8192] = {};
        DWORD rd = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
        CloseHandle(h);
        std::string text(buf, rd);
        const std::string k = narrow + "=";
        size_t pos = 0;
        while (pos <= text.size()) {
            size_t e2 = text.find('\n', pos);
            if (e2 == std::string::npos) e2 = text.size();
            std::string line = text.substr(pos, e2 - pos);
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(0, 1);
            if (line.compare(0, k.size(), k) == 0) { v = line.substr(k.size()); break; }
            if (e2 == text.size()) break;
            pos = e2 + 1;
        }
    }
    return v.empty() ? std::string(defVal) : v;
}

bool OptBool(const char* envName, const wchar_t* iniKey, bool defVal) {
    std::string v = Opt(envName, iniKey, defVal ? "1" : "0");
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

int OptInt(const char* envName, const wchar_t* iniKey, int defVal) {
    std::string v = Opt(envName, iniKey, "");
    if (v.empty()) return defVal;
    int n = atoi(v.c_str());
    return n > 0 ? n : defVal;
}

// 安全模式判定：SM_CLEANBOOT 非 0 即安全模式（1=安全模式，2=带网络）
bool InSafeMode() { return GetSystemMetrics(SM_CLEANBOOT) != 0; }

bool PidAlive(unsigned long pid) {
    if (pid == 0) return false;
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

unsigned long ReadPidFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    char buf[64] = {};
    DWORD rd = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    return (unsigned long)strtoul(buf, nullptr, 10);
}

void WritePidFile(const std::wstring& path, unsigned long pid) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[32] = {};
    int n = wsprintfA(buf, "%lu", pid);
    DWORD wr = 0;
    WriteFile(h, buf, (DWORD)n, &wr, nullptr);
    CloseHandle(h);
}

unsigned long ReadGuardPid() { return ReadPidFile(GuardPidFile()); }
unsigned long ReadMainPid()  { return ReadPidFile(MainPidFile()); }

bool StopMarkerExists() {
    return GetFileAttributesW(StopFile().c_str()) != INVALID_FILE_ATTRIBUTES;
}

void ClearStopMarker() { DeleteFileW(StopFile().c_str()); }

// 用同一个 exe 拉起自己，args 为附加参数
bool SpawnSelf(const wchar_t* args, bool detached) {
    std::wstring cmd = L"\"" + SelfPath() + L"\"";
    if (args && *args) { cmd += L" "; cmd += args; }
    std::vector<wchar_t> mut(cmd.begin(), cmd.end());
    mut.push_back(L'\0');
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    DWORD flags = CREATE_NO_WINDOW | (detached ? DETACHED_PROCESS : 0);
    // 工作目录设成 exe 所在目录：主进程要靠相对路径找到 r6m.ini
    std::wstring dir = ExeDir();
    if (!CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE, flags,
                        nullptr, dir.c_str(), &si, &pi)) {
        LOG_W(SG_TAG, ("SelfGuard: 拉起进程失败 err=" + std::to_string(GetLastError())).c_str());
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}


// ── 自自启动配置用到的三个 helper（本文件内部）──────────────────────────────────
// 跑一条命令并等它结束，返回退出码（-1 = 起不来）
DWORD SelfTaskRun(const std::wstring& cmd) {
    std::vector<wchar_t> mut(cmd.begin(), cmd.end());
    mut.push_back(L'\0');
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return (DWORD)-1;
    }
    WaitForSingleObject(pi.hProcess, 20000);
    DWORD rc = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}

// ── 用 XML 建任务 ────────────────────────────────────────────────────────────
// 为什么不用命令行开关：这些设置命令行表达不了，而其中两条是**必须**的 ——
//     （那会让"常驻"变成"三天后自己没了"，而且极难查）
std::wstring BuildSelfTaskXml(const std::wstring& exe, const std::wstring& dir) {
    std::wstring x;
    x += L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n";
    x += L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n";
    x += L"  <RegistrationInfo><Description>client supervisor</Description></RegistrationInfo>\r\n";
    x += L"  <Triggers>\r\n";
    x += L"    <BootTrigger><Enabled>true</Enabled></BootTrigger>\r\n";
    x += L"    <TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary>\r\n";
    x += L"      <Repetition><Interval>PT2M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>\r\n";
    x += L"      <Enabled>true</Enabled></TimeTrigger>\r\n";
    x += L"  </Triggers>\r\n";
    x += L"  <Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n";
    x += L"  <Settings>\r\n";
    x += L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n";
    x += L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n";
    x += L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n";
    x += L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n";
    x += L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n";
    x += L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n";
    x += L"    <Enabled>true</Enabled>\r\n";
    x += L"    <Hidden>false</Hidden>\r\n";
    x += L"    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>\r\n";
    x += L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n";
    x += L"    <Priority>7</Priority>\r\n";
    x += L"  </Settings>\r\n";
    x += L"  <Actions Context=\"Author\"><Exec><Command>" + exe + L"</Command>";
    if (!dir.empty()) x += L"<WorkingDirectory>" + dir + L"</WorkingDirectory>";
    x += L"</Exec></Actions>\r\n";
    x += L"</Task>\r\n";
    return x;
}

// 写出 XML（UTF-16LE + BOM：schtasks /XML 最稳的形态）并用它建任务；返回 schtasks 退出码
DWORD SelfTaskCreateXml(const std::wstring& task, const std::wstring& exe, const std::wstring& dir) {
    wchar_t tdir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tdir)) return (DWORD)-1;
    const std::wstring file = std::wstring(tdir) + L"r6m_task_" + std::to_wstring(GetCurrentProcessId()) + L".xml";
    const std::wstring xml = BuildSelfTaskXml(exe, dir);
    {
        HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h == INVALID_HANDLE_VALUE) return (DWORD)-1;
        const unsigned char bom[2] = { 0xFF, 0xFE };
        DWORD wr = 0;
        WriteFile(h, bom, 2, &wr, nullptr);
        WriteFile(h, xml.data(), (DWORD)(xml.size() * sizeof(wchar_t)), &wr, nullptr);
        CloseHandle(h);
    }
    const DWORD rc = SelfTaskRun(L"schtasks.exe /Create /TN \"" + task + L"\" /XML \"" + file + L"\" /F");
    DeleteFileW(file.c_str());
    return rc;
}

// 把 schtasks /Query /XML 的输出重定向到临时文件再读回，在字节层搜两个特征。
// 为什么这么绕：schtasks 的 XML 输出是 UTF-16，宽串的字节直接可比，不必解码；
// 而"任务不存在"时 rc!=0 属正常路径，不是错误。
// 返回 false 只表示查询过程本身出错。
// 在字节流里找宽串：UTF-16LE 与（纯 ASCII 时）窄字节两种都试。
bool SelfBytesContain(const std::string& hay, const std::wstring& needle) {
    if (needle.empty() || hay.empty()) return false;
    const char* w = (const char*)needle.data();
    const size_t wn = needle.size() * sizeof(wchar_t);
    if (hay.size() >= wn && std::search(hay.begin(), hay.end(), w, w + wn) != hay.end()) return true;
    std::string narrow;
    narrow.reserve(needle.size());
    for (wchar_t c : needle) {
        if (c > 127) return false;              // 非 ASCII 无法用窄字节表示，只认 UTF-16
        narrow.push_back((char)c);
    }
    return std::search(hay.begin(), hay.end(), narrow.begin(), narrow.end()) != hay.end();
}

bool SelfTaskQuery(const std::wstring& task, const std::wstring& exe,
                   bool& exists, bool& pointsHere, bool& isSystem) {
    exists = pointsHere = isSystem = false;
    wchar_t tdir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tdir)) return false;
    std::wstring file = std::wstring(tdir) + L"r6m_q_" + std::to_wstring(GetCurrentProcessId()) + L".xml";
    DeleteFileW(file.c_str());

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::wstring cmd = L"schtasks.exe /Query /TN \"" + task + L"\" /XML";
    std::vector<wchar_t> mut(cmd.begin(), cmd.end());
    mut.push_back(L'\0');
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = h;
    si.hStdError = h;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {};
    DWORD rc = (DWORD)-1;
    if (CreateProcessW(nullptr, mut.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        GetExitCodeProcess(pi.hProcess, &rc);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    std::string bytes;
    {
        LARGE_INTEGER sz = {};
        if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (16 << 20)) {
            bytes.resize((size_t)sz.QuadPart);
            LARGE_INTEGER z = {};
            SetFilePointerEx(h, z, nullptr, FILE_BEGIN);
            DWORD got = 0;
            ReadFile(h, &bytes[0], (DWORD)bytes.size(), &got, nullptr);
            bytes.resize(got);
        }
    }
    CloseHandle(h);
    DeleteFileW(file.c_str());
    if (rc != 0 || bytes.empty()) return true;      // 任务不存在：正常路径

    exists = true;
    pointsHere = SelfBytesContain(bytes, exe);
    // SYSTEM 的 SID 在任务 XML 里形如 <UserId>S-1-5-18</UserId>（UTF-16）
    isSystem = SelfBytesContain(bytes, L"S-1-5-18") || SelfBytesContain(bytes, L"SYSTEM");
    return true;
}

// 读 r6m.ini 的自自启动配置开关（自包含读取，不依赖别处的解析顺序）
void SelfTaskReadIni(bool& enabled, std::wstring& taskName) {
    enabled = true;                                     // 默认开：要求"起来就给自己建"
    taskName = L"R6MClientSupervisor";                  // 复用既有任务名，不多留一个痕迹
    std::ifstream ini((ExeDir() + L"\\r6m.ini").c_str());
    if (!ini.is_open()) return;
    std::string line;
    while (std::getline(ini, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), val = line.substr(eq + 1);
        if (key == "persist") {
            enabled = !(val == "0" || val == "off" || val == "false");
        } else if (key == "persist_name" && !val.empty()) {
            taskName.assign(val.begin(), val.end());
        }
    }
}

// ── 自启（只在显式要求时做；错在哪一步都要如实记录）───────────────────────
void ApplyPersistence(bool enable) {
    const wchar_t* kTask = L"R6MClientSupervisor";
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring tr = L"\"" + std::wstring(exe) + L"\"";

    // 计划任务：登录时以最高权限起（/RL HIGHEST）
    std::wstring cmd = std::wstring(L"schtasks ") + (enable ? L"/Create " : L"/Delete ") +
                       L"/TN \"" + kTask + L"\" " +
                       (enable ? (L"/SC ONLOGON /TR \"" + tr + L"\" /RL HIGHEST /F")
                               : L"/F");
    std::vector<wchar_t> mut(cmd.begin(), cmd.end());
    mut.push_back(L'\0');
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    DWORD taskRc = (DWORD)-1;
    if (CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 20000);
        GetExitCodeProcess(pi.hProcess, &taskRc);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    // 如实记录成功/失败：以前这里打印"已设置"却不看返回码，排查时被误导过
    LOG_I(SG_TAG, (std::string(enable ? "计划任务设置" : "计划任务删除") +
                   (taskRc == 0 ? "=成功" : "=失败 rc=" + std::to_string(taskRc))).c_str());

    // HKCU Run 键（双保险；受管端常以当前用户身份跑，这条最稳）
    HKEY hk = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr,
                        0, KEY_SET_VALUE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        LONG rc;
        if (enable) {
            const wchar_t* val = exe;
            rc = RegSetValueExW(hk, kTask, 0, REG_SZ, (const BYTE*)val,
                                (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
        } else {
            rc = RegDeleteValueW(hk, kTask);
        }
        LOG_I(SG_TAG, (std::string(enable ? "Run键设置" : "Run键删除") +
                       (rc == ERROR_SUCCESS ? "=成功" : "=失败 rc=" + std::to_string(rc))).c_str());
        RegCloseKey(hk);
    } else {
        LOG_W(SG_TAG, "打开 Run 键失败（自启没设上）");
    }
}

} // namespace

// ═══ 常驻进程主循环 ═════════════════════════════════════════════════════════

int SelfGuard::RunGuardian() {
    // **常驻单实例**：抢不到互斥体说明已有常驻在跑，直接退出。
    // 这是兜底 —— 就算 pid 逻辑再出错，也不可能出现第二个常驻把进程数滚大。
    HANDLE singleton = CreateMutexW(nullptr, TRUE, L"R6MClientGuardSingleton");
    if (singleton && GetLastError() == ERROR_ALREADY_EXISTS) {
        LOG_I(SG_TAG, "SelfGuard: 已有常驻在运行，本实例退出（单实例约束）");
        CloseHandle(singleton);
        return 0;
    }

    unsigned long target = ReadMainPid();
    LOG_I(SG_TAG, ("SelfGuard: 常驻启动，监视 pid=" + std::to_string(target)).c_str());

    if (InSafeMode()) {
        LOG_W(SG_TAG, "SelfGuard: 安全模式，常驻不复活（救援环境不做兼容）");
        return 0;
    }

    const int  maxRestarts = OptInt("R6M_GUARD_MAX", L"guard_max", 3);
    const DWORD windowMs   = 120000;   // 判定窗口
    int  restarts = 0;
    DWORD winStart = GetTickCount();

    // 常驻只写**自己**的文件；主进程的 pid 由主进程维护（两个文件各管一件事）
    WritePidFile(GuardPidFile(), GetCurrentProcessId());
    ClearStopMarker();

    while (true) {
        // 优雅退出的暗号：主进程自己走的，不复活
        if (StopMarkerExists()) {
            LOG_I(SG_TAG, "SelfGuard: 主进程优雅退出（见到 stop 标记），常驻随之退出");
            return 0;
        }

        if (!PidAlive(target)) {
            LOG_W(SG_TAG, ("SelfGuard: 主进程 pid=" + std::to_string(target) +
                           " 已不在，准备复活").c_str());

            const DWORD now = GetTickCount();
            if (now - winStart > windowMs) { winStart = now; restarts = 0; }
            restarts++;
            if (restarts > maxRestarts) {
                LOG_W(SG_TAG, ("SelfGuard: " + std::to_string(windowMs / 1000) +
                               " 秒内已被结束 " + std::to_string(maxRestarts) +
                               " 次以上 —— 判定为管理员在手动关闭，常驻退出并撤掉自启").c_str());
                ApplyPersistence(false);
                return 0;
            }
            LOG_I(SG_TAG, ("SelfGuard: 重新拉起主进程（第 " + std::to_string(restarts) +
                           "/" + std::to_string(maxRestarts) + " 次）").c_str());
            if (!SpawnSelf(nullptr, true)) {
                LOG_W(SG_TAG, "SelfGuard: 拉起失败，常驻继续尝试");
            }
            // 给新进程一点时间写 main.pid，再继续盯它（读不到就下轮再读）
            Sleep(3000);
            target = ReadMainPid();
            continue;
        }

        // 目标还活着：小睡一轮（用短超时以便及时看到 stop 标记）
        Sleep(1500);
    }
}

// ═══ 主进程入口 ════════════════════════════════════════════════════════════

bool SelfGuard::IsGuardianMode() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;
    bool found = false;
    for (int i = 1; i < argc; i++) {
        if (std::wstring(argv[i]) == kGuardFlag) { found = true; break; }
    }
    LocalFree(argv);
    return found;
}

void SelfGuard::Init() {
    const bool armed = OptBool("R6M_SELFPROTECT", L"selfprotect", false);
    if (!armed) {
        // 刻意安静：默认不开，也不刷日志
        return;
    }
    if (InSafeMode()) {
        LOG_W(SG_TAG, "SelfGuard: 安全模式，不启用进程保护");
        return;
    }

    // 先把自己的 pid 落盘：常驻就是靠这个文件找到"该盯谁"的。
    // （复活后 pid 会变，所以每次启动都要重写，不能让常驻去猜。）
    WritePidFile(MainPidFile(), GetCurrentProcessId());

    // 已有活着的常驻就不再拉 —— 判据必须是**常驻自己的** pid 文件。
    // 上一版读的是被双方共用的那个文件，读到的是旧主进程的 pid，
    // 于是每次复活都新拉一个常驻（实测攒出 5 个）。
    unsigned long guard = ReadGuardPid();
    if (guard != 0 && guard != GetCurrentProcessId() && PidAlive(guard)) {
        LOG_I(SG_TAG, ("SelfGuard: 已有常驻 pid=" + std::to_string(guard) +
                       "，不重复拉起（本进程 pid=" + std::to_string(GetCurrentProcessId()) +
                       " 已写入 main.pid）").c_str());
        return;
    }

    ClearStopMarker();

    if (!SpawnSelf(kGuardFlag, true)) {
        LOG_W(SG_TAG, "SelfGuard: 常驻拉起失败（进程保护未生效）");
        return;
    }
    LOG_I(SG_TAG, "SelfGuard: 进程保护已启用（常驻互检）");

    // 这里**不再**调用 ApplyPersistence(true)：它用**同名任务** R6MClientSupervisor，
    // 自建任务已完全覆盖它的用途；ApplyPersistence 本体保留（它是显式操作的旧入口）。
}

void SelfGuard::Shutdown() {
    if (!OptBool("R6M_SELFPROTECT", L"selfprotect", false)) return;
    // 留暗号让常驻知道我（主进程）是优雅退出的，不要复活我
    HANDLE h = CreateFileW(StopFile().c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    LOG_I(SG_TAG, "SelfGuard: 已留 stop 标记，常驻不会复活本进程");
}

std::string SelfGuard::StatusLine() {
    std::string s = "SelfGuard: ";
    s += OptBool("R6M_SELFPROTECT", L"selfprotect", false) ? "已启用" : "未启用（默认关）";
    s += InSafeMode() ? " / 安全模式" : "";
    unsigned long p = ReadGuardPid();
    s += " / 常驻pid=" + std::to_string(p);
    if (p && p != GetCurrentProcessId()) s += PidAlive(p) ? "（存活）" : "（已退出）";
    s += " / main.pid=" + std::to_string(ReadMainPid());
    return s;
}


// ═══════════════════════════════════════════════════════════════════════════
// 自自启动配置：启动时给自己建计划任务，以最高权限把自己拉起来
//
// 与匿名命名空间里 ApplyPersistence 的关系（两个都留，用途不同）：
//   · ApplyPersistence：**显式调用**，只做 ONLOGON + /RL HIGHEST（要有人登录才起）
//   · EnsureSelfTask ：**每次启动自动做一次**，优先 ONSTART + SYSTEM（开机即起、不依赖登录），
//                      拿不到 SYSTEM 就自动退回 ONLOGON + HIGHEST
//
// 为什么用 schtasks.exe 而不是任务计划 COM：项目里已有两处这么做（ApplyPersistence、
//   ArtifactApply 的 ApplyTask），保持一致；且 CreateProcessW 直起 schtasks.exe 不经 cmd，
//   不受 DisableCMD 影响（那条策略由 cmd.exe 自己执行）。
//   代价：会短暂出现一个 schtasks.exe 子进程（可见性代价，写在这里以便日后权衡）。
//
// 幂等判据：**两条同时成立**才算"已就绪"，否则重建 ——
//   ① 任务 XML 里出现本 exe 路径；② 出现 SYSTEM 的 SID S-1-5-18。
//   只查 ① 会在"先以普通权限建过、后来提升权限了"的情况下永远升不到 SYSTEM（特意避免）。
//
// 成功/失败都写日志：本文件有过"打印已设置却不看返回码"的教训，这里两个 rc 都记。
// ═══════════════════════════════════════════════════════════════════════════
bool SelfGuard::EnsureSelfTask() {
    bool enabled = true;
    std::wstring task;
    SelfTaskReadIni(enabled, task);
    if (!enabled) {
        LOG_I(SG_TAG, "自自启动配置：r6m.ini 里 persist=0，跳过（不改动计划任务）");
        return false;
    }
    const std::wstring exe = SelfPath();

    //   实测教训：我先用「查 XML 里是否有本 exe 路径 + S-1-5-18」当就绪判据，
    //   所以 rc==0 就足以判定成功；下面的查询只用于打日志（查错也不会造成降级）。
    const DWORD rc1 = SelfTaskCreateXml(task, exe, ExeDir());
    if (rc1 == 0) {
        bool exists = false, here = false, sys = false;
        SelfTaskQuery(task, exe, exists, here, sys);
        LOG_I(SG_TAG, (std::string("自自启动配置：已建 SYSTEM 开机自启任务（rc=0）复核[存在=") +
                       (exists ? "是" : "否") + " 指向本exe=" + (here ? "是" : "否") +
                       " 含SYSTEM标记=" + (sys ? "是" : "否") + "] 任务=" +
                       std::string(task.begin(), task.end())).c_str());
        return true;
    }

    // 只有 SYSTEM 失败（通常是没提升权限）才退回：登录触发 + 最高权限（免 UAC 弹窗）
    const std::wstring cmdLog = L"schtasks.exe /Create /TN \"" + task +
                                L"\" /SC ONLOGON /RL HIGHEST /TR \"" + exe + L"\" /F";
    const DWORD rc2 = SelfTaskRun(cmdLog);
    if (rc2 == 0) {
        LOG_W(SG_TAG, (std::string("自自启动配置：SYSTEM 没建成（rc=") + std::to_string(rc1) +
                       "，多半是当前不是提升权限态），已退回登录触发+最高权限（rc=0）任务=" +
                       std::string(task.begin(), task.end())).c_str());
        return true;
    }

    LOG_E(SG_TAG, (std::string("自自启动配置失败：SYSTEM rc=") + std::to_string(rc1) +
                   "，登录触发 rc=" + std::to_string(rc2) + " 任务=" +
                   std::string(task.begin(), task.end())).c_str());
    return false;
}

} // namespace r6m
