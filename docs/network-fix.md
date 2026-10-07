# NetworkFix 实现详解

> 本文档于 2026-10-07 按实际代码重写。
> 上一版描述了一整套并不存在的 API（`FixResult diagnoseAndFix()` /
> `IPv6Status checkIPv6Status()` / `std::vector<Problem> diagnose()` /
> `FixResult applyFixes()` / `bool verifyConnectivity()` / `execCmd` /
> `pingIPv6` / `testTCP`），以及 MTU 检查、防火墙规则、四级验证等
> 代码里一行都没有的功能。现按 `client/src/NetworkFix.cpp` 的真实行为描述。

## 概述

`NetworkFix` 的职责非常窄：**在建立管理通道之前，让本机具备一条能到达服务端的
IPv6 路径**。它不是通用的 IPv6 体检工具。

对外只有两个入口（`client/src/NetworkFix.h`，全文 11 行）：

```cpp
class NetworkFix {
public:
    // 入口：路由 + DNS + 连通性验证
    static void FixAll(const std::string& serverUrl);
    // ping 服务端 IPv6，供 Stub 启动前调用
    static bool VerifyC2Reachable(const std::string& serverUrl);
};
```

## 实际执行流程（`FixAll`）

```
1. 从 serverUrl 里取方括号中的 IPv6（https://[240e:...::1]:8443 → 240e:...::1）
   取不到就直接返回（IPv4/域名场景不做任何事）
2. SetupIPv6Routes(target)   ← 枚举网卡，按需补路由
3. SetupIPv6DNS()            ← 保留原 IPv4 DNS，追加公共 IPv6 DNS，刷新缓存
4. PingC2(target)            ← ping -6 -n 3，仅记日志，失败不阻断
```

### SetupIPv6Routes 做什么

1. `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX)` 枚举所有网卡；
2. 跳过 `OperStatus != IfOperStatusUp` 与未启用 IPv6 的接口；
3. 找第一个**全球单播地址**（排除 link-local `fe80::/10`、ULA `fc00::/7`、`::`、`::1`），
   取其高 64 位作为 on-link 前缀：
   - `netsh interface ipv6 add route <prefix>::/64 interface=<idx>`（退出码 1 视为"已存在"，不算错）
   - 找该接口上的 link-local 网关，加 `netsh interface ipv6 add route ::/0 interface=<idx> nexthop=<gw>`
   - 没有网关时退化为 on-link 默认路由：`netsh interface ipv6 add route ::/0 interface=<idx>`
4. **兜底分支**：若所有接口都没有全球地址（典型：光猫没下发 RA/SLAAC），
   但有 link-local，则用「C2 的 /64 前缀 + 本机 link-local 主机标识」手工补一个地址，
   再补一条该前缀的直连路由。

`GetC2Prefix` 于 2026-10-07 修正：原实现"数到第 4 个冒号就截断"，遇到压缩写法
（`2001:db8::1` 只有 2 个冒号）会把整串当成前缀，拼出 `2001:db8::1::/64` 这种非法地址，
netsh 失败又被 `allowNonZero` 吞掉，导致兜底地址静默失效。现改为 `InetPtonW` 解析后
按字节取高 64 位，任何合法写法都能得到正确前缀。

### SetupIPv6DNS 做什么

`Get-NetAdapter` → 逐个 Up 网卡 → 读出原 IPv4 DNS → `Set-DnsClientServerAddress`
把它与 `2400:3200::1`、`2400:3200::2` 一起写入 → `ipconfig /flushdns`。

2026-10-07 修正两处：
- 去掉 `-ExecutionPolicy Bypass`（`-Command` 本来不受执行策略约束，
  这个参数除了给端点安全产品一个显眼的可疑特征之外没有任何作用）；
- 删掉固定 `nslookup your-domain.duckdns.org` —— 占位域名在任何真实环境都必然失败，
  只污染日志。DNS 是否生效由随后的 `PingC2` 与注册请求来判定。

## 明确未实现的能力（不要再按旧文档去"找"）

| 能力 | 现状 |
|---|---|
| `netsh interface ipv6 show global` 状态检查 / `set global disabled=false` | 未实现 |
| 接口地址 DHCPv6 重取（`set address ... dhcp`） | 未实现 |
| MTU 检查与修正（`set subinterfaces mtu=`） | 未实现 |
| 防火墙 ICMPv6 规则增删（`advfirewall firewall add rule`） | 未实现 |
| `netsh interface ipv6 reset` | 未实现（破坏性操作，刻意不做） |
| TCP 层连通性测试（`testTCP`） | 未实现 |
| HTTP 层验证 | 未实现（由 Stub 的 `/api/health` 探测间接覆盖） |
| 修复前后状态留痕 / 回滚 | 未实现（只写日志） |

`docs/ipv6-repair.md` 里的诊断命令仍然有效，但那是**人工排查手册**，
不是本模块的自动化行为。

## 失败可见性

`RunCmd` 会把命令原文、退出码与成功/失败判定写进 `client.log`；
`SetupIPv6Routes` / `SetupIPv6DNS` 的每一步都有 `=== ... start/done ===` 标记。
2026-10-07 起，`RunCmd` 的命令行缓冲改为按需分配（原来 `wcscpy_s` 到固定 4096
缓冲，超长命令会触发无效参数处理器直接终止进程）。

需要人工复核时：`client.log` 里按 `NetFix` 过滤即可看到每条 netsh 的退出码。
