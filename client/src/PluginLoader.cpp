#include "PluginLoader.h"
#include "Logger.h"
#include "Json.h"
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

// ── 宽窄转换 ──
// 修复点：原实现先构造 (len-1) 长度的字符串，再把 len 字节（含结尾 NUL）写进去，
// 等于越界写 1 字节。正确做法是先按 len 开缓冲，让 API 写满，再按需截掉结尾 NUL。
static std::string WsToUtf8(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring w((size_t)len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

void PluginLoader::scanPlugins(const std::wstring& pluginDir) {
    LOG_I("PluginLoader", "Scanning plugins...");
    _configs.clear();
    if (!fs::exists(pluginDir)) { LOG_W("PluginLoader", "Plugin dir not found"); return; }
    for (const auto& dir : fs::directory_iterator(pluginDir)) {
        if (!dir.is_directory()) continue;
        auto jsonPath = dir.path() / "plugin.json";
        if (!fs::exists(jsonPath)) continue;
        std::ifstream ifs(jsonPath, std::ios::binary);
        if (!ifs.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

        // 用真 JSON 解析：原来按 "\"key\"" 找引号位置，值里含转义引号/换行就会取错
        r6m::Json j;
        std::string err;
        if (!r6m::Json::parse(content, j, &err)) {
            LOG_W("PluginLoader", ("plugin.json 解析失败，跳过: " + WsToUtf8(dir.path().filename().wstring()) + " -> " + err).c_str());
            continue;
        }
        PluginConfig cfg;
        cfg.id = WsToUtf8(dir.path().filename().wstring());
        cfg.name = j.getString("name");
        cfg.version = j.getString("version");
        cfg.command = j.getString("command");
        cfg.description = j.getString("description");
        if (cfg.command.empty()) { LOG_W("PluginLoader", ("Skip: " + cfg.id + " no command").c_str()); continue; }
        cfg.workDir = WsToUtf8(dir.path().wstring());
        _configs.push_back(cfg);
        LOG_I("PluginLoader", ("Found: " + cfg.name + " v" + cfg.version + " cmd=" + cfg.command).c_str());
    }
    LOG_I("PluginLoader", ("Scanned " + std::to_string(_configs.size()) + " plugins").c_str());
}

PluginProcess* PluginLoader::findProcess(const std::string& pluginId) {
    for (auto& p : _processes) { if (p.config.id == pluginId) return &p; }
    return nullptr;
}

void PluginLoader::startErrDrain(const std::string& pluginId, HANDLE hErr) {
    auto stopFlag = std::make_shared<std::atomic<bool>>(false);
    _errStop[pluginId] = stopFlag;
    _errThreads[pluginId] = std::thread([pluginId, hErr, stopFlag]() {
        char buf[4096];
        DWORD got = 0;
        int forwarded = 0;
        while (!stopFlag->load()) {
            DWORD avail = 0;
            if (!PeekNamedPipe(hErr, nullptr, 0, nullptr, &avail, nullptr)) break;  // 管道已关闭
            if (avail == 0) { Sleep(100); continue; }
            if (!ReadFile(hErr, buf, sizeof(buf) - 1, &got, nullptr) || got == 0) break;
            buf[got] = 0;
            // 前 20 条转发到客户端日志便于排障，之后只丢弃——
            // 关键是"必须一直读"，否则插件写 stderr 会阻塞在管道上
            if (forwarded < 20) {
                LOG_I("PluginStderr", ("[" + pluginId + "] " + std::string(buf, got)).c_str());
                forwarded++;
                if (forwarded == 20) {
                    LOG_I("PluginStderr", ("[" + pluginId + "] 后续 stderr 已丢弃（继续排空以免插件阻塞）").c_str());
                }
            }
        }
    });
}

void PluginLoader::stopErrDrain(const std::string& pluginId) {
    auto it = _errStop.find(pluginId);
    if (it != _errStop.end() && it->second) it->second->store(true);
    auto tt = _errThreads.find(pluginId);
    if (tt != _errThreads.end()) {
        if (tt->second.joinable()) tt->second.join();
        _errThreads.erase(tt);
    }
    _errStop.erase(pluginId);
}

PluginProcess* PluginLoader::startProcess(const PluginConfig& config) {
    LOG_I("PluginLoader", ("Starting: " + config.name).c_str());

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hInR = nullptr, hInW = nullptr, hOutR = nullptr, hOutW = nullptr, hErrR = nullptr, hErrW = nullptr;
    // 修复点：原来三个 CreatePipe 的返回值都不检查，失败时会把未初始化的句柄交给 CreateProcessW
    bool pipesOk = CreatePipe(&hInR, &hInW, &sa, 0) &&
                   CreatePipe(&hOutR, &hOutW, &sa, 0) &&
                   CreatePipe(&hErrR, &hErrW, &sa, 0);
    if (!pipesOk) {
        LOG_E("PluginLoader", ("CreatePipe failed err=" + std::to_string(GetLastError())).c_str());
        if (hInR) CloseHandle(hInR);
        if (hInW) CloseHandle(hInW);
        if (hOutR) CloseHandle(hOutR);
        if (hOutW) CloseHandle(hOutW);
        if (hErrR) CloseHandle(hErrR);
        if (hErrW) CloseHandle(hErrW);
        return nullptr;
    }
    SetHandleInformation(hInW, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.hStdInput = hInR;
    si.hStdOutput = hOutW;
    si.hStdError = hErrW;
    si.dwFlags = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION pi = {};
    std::wstring wd = Utf8ToWide(config.workDir);

    // ── 组装候选命令行 ──
    // 修复点：原来无条件执行 cmdW.substr(7)，任何短于 7 字符的 command
    // （例如 "lua x"）都会抛 std::out_of_range，一路冒泡到 main 的 catch(...)，
    // 表现为"客户端启动即退出，日志只有一行 EXCEPTION"。
    std::wstring cmdW = Utf8ToWide(config.command);
    std::vector<std::wstring> candidatesW;
    std::wstring scriptName;
    bool isPythonCmd = false;
    const std::wstring pyPrefix = L"python ";
    const std::wstring py3Prefix = L"python3 ";
    if (cmdW.size() > pyPrefix.size() && cmdW.compare(0, pyPrefix.size(), pyPrefix) == 0) {
        isPythonCmd = true;
        scriptName = cmdW.substr(pyPrefix.size());
    } else if (cmdW.size() > py3Prefix.size() && cmdW.compare(0, py3Prefix.size(), py3Prefix) == 0) {
        isPythonCmd = true;
        scriptName = cmdW.substr(py3Prefix.size());
    }

    if (isPythonCmd && !scriptName.empty()) {
        if (!_pythonPathW.empty()) candidatesW.push_back(L"\"" + _pythonPathW + L"\" " + scriptName);
        candidatesW.push_back(L"python " + scriptName);
        candidatesW.push_back(L"python3 " + scriptName);
        candidatesW.push_back(L"py " + scriptName);
    } else if (!cmdW.empty()) {
        candidatesW.push_back(cmdW);
    }
    if (candidatesW.empty()) {
        LOG_E("PluginLoader", ("无法为该插件组装命令行: " + config.command).c_str());
        CloseHandle(hInR); CloseHandle(hInW); CloseHandle(hOutR); CloseHandle(hOutW); CloseHandle(hErrR); CloseHandle(hErrW);
        return nullptr;
    }

    BOOL ok = FALSE;
    for (const auto& tryCmdW : candidatesW) {
        LOG_I("PluginLoader", ("  trying: " + WsToUtf8(tryCmdW)).c_str());
        std::vector<wchar_t> mutableCmd(tryCmdW.begin(), tryCmdW.end());
        mutableCmd.push_back(L'\0');
        ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                            nullptr, wd.c_str(), &si, &pi);
        if (ok) {
            LOG_I("PluginLoader", ("  success with: " + WsToUtf8(tryCmdW)).c_str());
            break;
        }
    }

    CloseHandle(hInR); CloseHandle(hOutW); CloseHandle(hErrW);
    if (!ok) {
        LOG_E("PluginLoader", ("Failed: " + config.name + " err=" + std::to_string(GetLastError()) +
                               " cmd=" + config.command + " dir=" + config.workDir).c_str());
        CloseHandle(hInW); CloseHandle(hOutR); CloseHandle(hErrR);
        return nullptr;
    }

    PluginProcess proc;
    proc.config = config;
    proc.hProcess = pi.hProcess;
    proc.hStdIn = hInW;
    proc.hStdOut = hOutR;
    proc.hStdErr = hErrR;
    proc.running = true;
    _processes.push_back(proc);
    CloseHandle(pi.hThread);
    LOG_I("PluginLoader", ("Started PID=" + std::to_string(pi.dwProcessId)).c_str());

    // stderr 必须持续排空，否则插件写满管道会永久阻塞（表现为所有调用超时）
    startErrDrain(config.id, hErrR);
    return &_processes.back();
}

bool PluginLoader::startPlugin(const std::string& pluginId) {
    if (findProcess(pluginId)) { LOG_W("PluginLoader", ("Already running: " + pluginId).c_str()); return true; }
    for (const auto& cfg : _configs) {
        if (cfg.id == pluginId) { auto* p = startProcess(cfg); return p != nullptr; }
    }
    LOG_E("PluginLoader", ("Not found: " + pluginId).c_str());
    return false;
}

void PluginLoader::stopPlugin(const std::string& pluginId) {
    auto* proc = findProcess(pluginId);
    if (!proc || !proc->running) return;
    LOG_I("PluginLoader", ("Stopping: " + pluginId).c_str());

    // 优雅退出：发带 id 的 shutdown 请求（三个插件都已实现），
    // 原来发的无 id 通知在插件侧是 unknown method，只能等 2 秒再强杀
    int id = _nextId++;
    r6m::Json req = r6m::Json::makeObject();
    req.set("jsonrpc", r6m::Json::makeString("2.0"));
    req.set("id", r6m::Json::makeNumber(id));
    req.set("method", r6m::Json::makeString("shutdown"));
    std::string line = req.dump() + "\n";
    DWORD written = 0;
    WriteFile(proc->hStdIn, line.c_str(), (DWORD)line.size(), &written, nullptr);

    if (WaitForSingleObject(proc->hProcess, 3000) == WAIT_TIMEOUT) {
        LOG_W("PluginLoader", ("插件未在 3 秒内退出，强制终止: " + pluginId).c_str());
        TerminateProcess(proc->hProcess, 0);
        WaitForSingleObject(proc->hProcess, 2000);
    }

    stopErrDrain(pluginId);   // 先让排空线程退出，再关句柄
    CloseHandle(proc->hProcess);
    CloseHandle(proc->hStdIn);
    CloseHandle(proc->hStdOut);
    CloseHandle(proc->hStdErr);
    proc->running = false;
}

void PluginLoader::stopAll() {
    for (auto& p : _processes) { if (p.running) stopPlugin(p.config.id); }
    _processes.clear();
}

// 读一行（\n 分帧）。返回空串＝超时或管道关闭。
std::string PluginLoader::readLine(PluginProcess* proc, int timeoutMs) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)timeoutMs) {
        // 缓冲里已有完整行就直接切出来
        size_t nl = proc->rxbuf.find('\n');
        if (nl != std::string::npos) {
            std::string line = proc->rxbuf.substr(0, nl);
            proc->rxbuf.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        DWORD avail = 0;
        if (!PeekNamedPipe(proc->hStdOut, nullptr, 0, nullptr, &avail, nullptr)) return std::string();
        if (avail == 0) { Sleep(20); continue; }
        char buf[8192];
        DWORD got = 0;
        if (!ReadFile(proc->hStdOut, buf, sizeof(buf), &got, nullptr) || got == 0) return std::string();
        proc->rxbuf.append(buf, got);
        if (proc->rxbuf.size() > (16u << 20)) {   // 单条消息上限 16MB，防止无换行的洪泛
            LOG_E("PluginLoader", "插件输出单行超过 16MB，丢弃缓冲");
            proc->rxbuf.clear();
            return std::string();
        }
    }
    return std::string();
}

std::string PluginLoader::callPlugin(const std::string& pluginId, const std::string& method,
                                     const std::string& params, int timeoutMs) {
    auto* proc = findProcess(pluginId);
    if (!proc || !proc->running) {
        if (!startPlugin(pluginId)) return std::string("{\"error\":\"plugin not found\"}");
        proc = findProcess(pluginId);
        if (!proc || !proc->running) return std::string("{\"error\":\"plugin failed to start\"}");
    }

    int id = _nextId++;
    r6m::Json req = r6m::Json::makeObject();
    req.set("jsonrpc", r6m::Json::makeString("2.0"));
    req.set("id", r6m::Json::makeNumber(id));
    req.set("method", r6m::Json::makeString(method));
    // params 是上游给的原始 JSON：先解析再嵌入，绝不字符串拼接
    // （原来直接拼进请求体，命令里含换行/引号就能破坏 JSON-RPC 帧）
    r6m::Json pj;
    std::string perr;
    if (params.empty() || !r6m::Json::parse(params, pj, &perr)) {
        if (!params.empty()) LOG_W("PluginLoader", ("params 非法 JSON，按空对象发送: " + perr).c_str());
        pj = r6m::Json::makeObject();
    }
    req.set("params", pj);

    std::string line = req.dump() + "\n";
    DWORD written = 0;
    if (!WriteFile(proc->hStdIn, line.c_str(), (DWORD)line.size(), &written, nullptr) || written != line.size()) {
        LOG_E("PluginLoader", ("写插件 stdin 失败: " + pluginId).c_str());
        return std::string("{\"error\":\"write to plugin failed\"}");
    }

    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)timeoutMs) {
        int remain = (int)((DWORD)timeoutMs - (GetTickCount() - start));
        if (remain <= 0) break;
        std::string rl = readLine(proc, remain);
        if (rl.empty()) continue;

        r6m::Json resp;
        std::string rerr;
        if (!r6m::Json::parse(rl, resp, &rerr) || !resp.isObject()) {
            // stdout 上出现非 JSON（插件把日志打到 stdout 了）：忽略并继续等应答
            LOG_W("PluginLoader", ("忽略插件的非 JSON 输出: " + rl.substr(0, 120)).c_str());
            continue;
        }
        const r6m::Json* rid = resp.find("id");
        if (rid && rid->isNumber() && (int)rid->number != id) {
            LOG_D("PluginLoader", ("跳过其它请求的应答 id=" + std::to_string((int)rid->number)).c_str());
            continue;
        }
        const r6m::Json* res = resp.find("result");
        if (res) return res->dump();
        const r6m::Json* err = resp.find("error");
        if (err) return std::string("{\"error\":") + err->dump() + "}";
        return resp.dump();
    }
    LOG_E("PluginLoader", ("调用插件超时: " + pluginId + "/" + method).c_str());
    return std::string("{\"error\":\"plugin timeout\"}");
}

std::string PluginLoader::listAllTools() {
    r6m::Json tools = r6m::Json::makeArray();
    _toolToPlugin.clear();
    for (const auto& cfg : _configs) {
        std::string resp = callPlugin(cfg.id, "tools/list", "{}", 5000);
        r6m::Json j;
        std::string err;
        if (!r6m::Json::parse(resp, j, &err)) {
            LOG_W("PluginLoader", ("tools/list 响应非法: " + cfg.id + " -> " + err).c_str());
            continue;
        }
        const r6m::Json* arr = j.find("tools");
        if (!arr || !arr->isArray()) continue;
        for (const auto& t : arr->items) {
            if (!t.isObject()) continue;
            std::string name = t.getString("name");
            if (name.empty()) continue;
            _toolToPlugin[name] = cfg.id;      // 只取 tools[] 顶层的 name
            r6m::Json item = r6m::Json::makeObject();
            item.set("name", r6m::Json::makeString(name));
            item.set("description", r6m::Json::makeString(t.getString("description")));
            item.set("plugin", r6m::Json::makeString(cfg.id));
            const r6m::Json* schema = t.find("inputSchema");
            if (schema) item.set("inputSchema", *schema);
            tools.push(item);
        }
    }
    r6m::Json out = r6m::Json::makeObject();
    out.set("tools", tools);
    LOG_I("PluginLoader", ("工具映射总数: " + std::to_string(_toolToPlugin.size())).c_str());
    return out.dump();
}

void PluginLoader::buildToolMap() {
    LOG_I("PluginLoader", "Building tool→plugin map...");
    listAllTools();
}

std::string PluginLoader::resolvePluginForTool(const std::string& toolName) const {
    auto it = _toolToPlugin.find(toolName);
    if (it != _toolToPlugin.end()) return it->second;
    return std::string();
}
