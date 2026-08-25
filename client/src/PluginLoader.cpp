#include "PluginLoader.h"
#include "Logger.h"
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

static std::string WsToUtf8(const std::wstring& ws) {
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), len, nullptr, nullptr);
    return s;
}

void PluginLoader::scanPlugins(const std::wstring& pluginDir) {
    LOG_I("PluginLoader", "Scanning plugins...");
    _configs.clear();
    if (!fs::exists(pluginDir)) { LOG_W("PluginLoader", "Plugin dir not found"); return; }
    for (const auto& dir : fs::directory_iterator(pluginDir)) {
        if (!dir.is_directory()) continue;
        auto jsonPath = dir.path() / "plugin.json";
        if (!fs::exists(jsonPath)) continue;
        std::ifstream ifs(jsonPath);
        if (!ifs.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        PluginConfig cfg;
        cfg.id = WsToUtf8(dir.path().filename().wstring());
        auto extract = [&](const std::string& key) -> std::string {
            auto pos = content.find("\"" + key + "\"");
            if (pos == std::string::npos) return "";
            pos = content.find(':', pos) + 1;
            pos = content.find('"', pos) + 1;
            auto end = content.find('"', pos);
            return content.substr(pos, end - pos);
        };
        cfg.name = extract("name");
        cfg.version = extract("version");
        cfg.command = extract("command");
        cfg.description = extract("description");
        if (cfg.command.empty()) { LOG_W("PluginLoader", ("Skip: " + cfg.id + " no command").c_str()); continue; }
        cfg.workDir = WsToUtf8(dir.path().wstring());
        _configs.push_back(cfg);
        LOG_I("PluginLoader", ("Found: " + cfg.name + " v" + cfg.version).c_str());
    }
    LOG_I("PluginLoader", ("Scanned " + std::to_string(_configs.size()) + " plugins").c_str());
}

PluginProcess* PluginLoader::findProcess(const std::string& pluginId) {
    for (auto& p : _processes) { if (p.config.id == pluginId) return &p; }
    return nullptr;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
    return w;
}

PluginProcess* PluginLoader::startProcess(const PluginConfig& config) {
    LOG_I("PluginLoader", ("Starting: " + config.name).c_str());
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hInR, hInW, hOutR, hOutW, hErrR, hErrW;
    CreatePipe(&hInR, &hInW, &sa, 0);
    CreatePipe(&hOutR, &hOutW, &sa, 0);
    CreatePipe(&hErrR, &hErrW, &sa, 0);
    SetHandleInformation(hInW, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrR, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = { sizeof(si) };
    si.hStdInput = hInR; si.hStdOutput = hOutW; si.hStdError = hErrW;
    si.dwFlags = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION pi = {};
    std::wstring wd = Utf8ToWide(config.workDir);

    // 构建候选命令列表（宽字符，支持中文路径）
    std::vector<std::wstring> candidatesW;
    std::wstring cmdW = Utf8ToWide(config.command);
    std::wstring scriptName = cmdW.substr(7); // "shell_exec.py"

    // 优先用嵌入式 Python（宽字符串路径，不丢中文）
    if (!_pythonPathW.empty() && cmdW.size() >= 7 && cmdW.substr(0, 7) == L"python ") {
        candidatesW.push_back(L"\"" + _pythonPathW + L"\" " + scriptName);
    }
    // 兜底：尝试系统 python/python3/py
    if (cmdW.size() >= 7 && cmdW.substr(0, 7) == L"python ") {
        if (candidatesW.empty()) {
            candidatesW.push_back(L"python " + scriptName);
        }
        candidatesW.push_back(L"python3 " + scriptName);
        candidatesW.push_back(L"py " + scriptName);
    } else {
        candidatesW.push_back(cmdW);
    }

    BOOL ok = FALSE;
    for (const auto& tryCmdW : candidatesW) {
        // 关闭上一次的句柄（如果需要重试）
        if (!ok) {
            // 首次不需要关闭，句柄还没被赋值
        }
        LOG_I("PluginLoader", ("  trying: " + WsToUtf8(tryCmdW)).c_str());
        ok = CreateProcessW(nullptr, (LPWSTR)tryCmdW.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, wd.c_str(), &si, &pi);
        if (ok) {
            LOG_I("PluginLoader", ("  success with: " + WsToUtf8(tryCmdW)).c_str());
            break;
        }
    }

    CloseHandle(hInR); CloseHandle(hOutW); CloseHandle(hErrW);
    if (!ok) {
        LOG_E("PluginLoader", ("Failed: " + config.name + " err=" + std::to_string(GetLastError()) + " cmd=" + config.command + " dir=" + config.workDir).c_str());
        CloseHandle(hInW); CloseHandle(hOutR); CloseHandle(hErrR); return nullptr;
    }
    PluginProcess proc;
    proc.config = config; proc.hProcess = pi.hProcess; proc.hStdIn = hInW;
    proc.hStdOut = hOutR; proc.hStdErr = hErrR; proc.running = true;
    _processes.push_back(proc);
    CloseHandle(pi.hThread);
    LOG_I("PluginLoader", ("Started PID=" + std::to_string(pi.dwProcessId)).c_str());
    return &_processes.back();
}

bool PluginLoader::startPlugin(const std::string& pluginId) {
    if (findProcess(pluginId)) { LOG_W("PluginLoader", ("Already running: " + pluginId).c_str()); return true; }
    for (const auto& cfg : _configs) { if (cfg.id == pluginId) { auto* p = startProcess(cfg); return p != nullptr; } }
    LOG_E("PluginLoader", ("Not found: " + pluginId).c_str());
    return false;
}

void PluginLoader::stopPlugin(const std::string& pluginId) {
    auto* proc = findProcess(pluginId);
    if (!proc || !proc->running) return;
    LOG_I("PluginLoader", ("Stopping: " + pluginId).c_str());
    std::string s = R"({"jsonrpc":"2.0","method":"shutdown"})";
    DWORD written = 0;
    WriteFile(proc->hStdIn, s.c_str(), s.size(), &written, nullptr);
    WriteFile(proc->hStdIn, "\n", 1, &written, nullptr);
    if (WaitForSingleObject(proc->hProcess, 2000) == WAIT_TIMEOUT) TerminateProcess(proc->hProcess, 0);
    CloseHandle(proc->hProcess); CloseHandle(proc->hStdIn); CloseHandle(proc->hStdOut); CloseHandle(proc->hStdErr);
    proc->running = false;
}

void PluginLoader::stopAll() { for (auto& p : _processes) { if (p.running) stopPlugin(p.config.id); } _processes.clear(); }

std::string PluginLoader::callPlugin(const std::string& pluginId, const std::string& method, const std::string& params, int timeoutMs) {
    auto* proc = findProcess(pluginId);
    if (!proc || !proc->running) {
        if (!startPlugin(pluginId)) return R"({"error":"plugin not found"})";
        proc = findProcess(pluginId);
        if (!proc || !proc->running) return R"({"error":"plugin failed"})";
    }
    std::string req = R"({"jsonrpc":"2.0","id":1,"method":")" + method + R"(","params":)" + params + "}\n";
    DWORD written = 0;
    WriteFile(proc->hStdIn, req.c_str(), req.size(), &written, nullptr);
    return readResponse(proc->hStdOut, timeoutMs);
}

std::string PluginLoader::readResponse(HANDLE hStdOut, int timeoutMs) {
    DWORD start = GetTickCount();
    std::string result;
    char buf[65536];
    while (GetTickCount() - start < (DWORD)timeoutMs) {
        DWORD avail = 0;
        PeekNamedPipe(hStdOut, nullptr, 0, nullptr, &avail, nullptr);
        if (avail == 0) { Sleep(50); continue; }
        DWORD bytesRead = 0;
        if (ReadFile(hStdOut, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buf[bytesRead] = 0; result += buf;
            int depth = 0; for (char c : result) { if (c == '{') depth++; else if (c == '}') depth--; }
            if (depth == 0 && !result.empty()) break;
        }
    }
    return result;
}

// 启动时遍历所有插件，发 tools/list 收集 工具名 → 插件ID
void PluginLoader::buildToolMap() {
    LOG_I("PluginLoader", "Building tool→plugin map...");
    _toolToPlugin.clear();
    for (const auto& cfg : _configs) {
        std::string resp = callPlugin(cfg.id, "tools/list", "{}", 5000);
        if (resp.empty()) continue;
        // 简化解析：找所有 "name":"xxx" 出现在 tools 数组里
        size_t pos = resp.find("\"tools\"");
        if (pos == std::string::npos) continue;
        size_t i = pos;
        while ((i = resp.find("\"name\"", i + 1)) != std::string::npos) {
            auto c1 = resp.find(':', i);
            auto q1 = resp.find('"', c1 + 1);
            auto q2 = resp.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos) {
                std::string tool = resp.substr(q1 + 1, q2 - q1 - 1);
                if (!tool.empty()) _toolToPlugin[tool] = cfg.id;
            } else break;
        }
        LOG_I("PluginLoader", ("  " + cfg.id + " tool map built").c_str());
    }
    LOG_I("PluginLoader", ("Total tools mapped: " + std::to_string(_toolToPlugin.size())).c_str());
}

std::string PluginLoader::resolvePluginForTool(const std::string& toolName) const {
    auto it = _toolToPlugin.find(toolName);
    if (it != _toolToPlugin.end()) return it->second;
    return "";
}
