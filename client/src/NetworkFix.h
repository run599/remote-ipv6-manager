#pragma once
#include <string>

class NetworkFix {
public:
    // 入口：路由 + DNS + 连通性验证
    // serverUrl: 如 "http://[2001:db8::1]:8080"，从中解析 IPv6 地址用于 ping
    static void FixAll(const std::string& serverUrl);
    // ping 服务端 IPv6，供 Stub 启动前调用
    static bool VerifyC2Reachable(const std::string& serverUrl);
};
