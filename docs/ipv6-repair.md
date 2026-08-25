# IPv6 自愈技术文档

## 为什么需要 IPv6 自愈？

国内大量用户的 IPv6 处于"半残疾"状态：
- 运营商分配了 IPv6 前缀，但路由器配置有误
- 设备获取了链路本地地址（fe80::），但没有全局地址（2xxx::）
- 有全局地址，但默认网关缺失
- 有网关，但 MTU 配置导致大包丢弃
- 有连接，但 Windows 防火墙阻断了入站

这些问题导致用户以为"IPv6 不通"，实际上是配置问题。

## 诊断流程

```
1. 检查 IPv6 是否启用
   → netsh interface ipv6 show global
   → 如果 disabled → netsh interface ipv6 set global disabled=false

2. 检查接口状态
   → netsh interface ipv6 show address
   → 关注：是否有 2xxx::/48 或 2xxx::/64 全局地址

3. 检查默认网关
   → netsh interface ipv6 show route
   → 关注：是否有 ::/0 路由指向 fe80::xx 链路本地地址

4. 测试连通性
   → ping6 -n 3 fe80::1%<interface>  (网关)
   → ping6 -n 3 2001:4860:4860::8888  (Google DNS)
   → 如果网关通外网不通 → 路由/前缀问题
   → 如果网关不通 → 链路层问题

5. 检查 MTU
   → netsh interface ipv6 show subinterfaces
   → 如果 MTU < 1280 → 修正为 1500

6. 检查防火墙
   → netsh advfirewall firewall show rule name="IPv6 ICMPv6"
   → 如果没有 → 添加允许 ICMPv6 的规则
```

## 常见修复命令

```bash
# 启用 IPv6
netsh interface ipv6 set global disabled=false

# 重置接口
netsh interface ipv6 reset

# 强制获取新地址
netsh interface ipv6 set address "以太网" dhcp
netsh interface ipv6 set dnsserver "以太网" dhcp

# 修正 MTU
netsh interface ipv6 set subinterfaces "以太网" mtu=1500 store=persistent

# 防火墙放行 ICMPv6
netsh advfirewall firewall add rule name="Allow ICMPv6 Echo" protocol=icmpv6:8,any dir=in action=allow
netsh advfirewall firewall add rule name="Allow ICMPv6 Neighbor" protocol=icmpv6:135,any dir=in action=allow

# 刷新路由
netsh interface ipv6 set route ::/0 "以太网" fe80::1 publish=yes
```

## 验证方法

修复后逐级验证：
1. `ipconfig /all` → 确认全局地址存在
2. `ping6 fe80::1%<if>` → 网关可达
3. `ping6 2001:4860:4860::8888` → 外网可达
4. `curl -6 http://[your-server]:8080/api/status` → 服务端可达

## 实际案例

### 案例 1：iStoreOS 路由器 IPv6 不通
**症状**：设备获取了 IPv6 地址，但 ping6 外网超时
**原因**：路由器 WAN 口 IPv6 PD（前缀委派）配置错误
**修复**：重新配置 PD，设置 WAN 口 DHCPv6-PD

### 案例 2：Windows 10 链路本地地址无全局地址
**症状**：`ipconfig` 显示 fe80:: 开头的地址，没有 2xxx:: 地址
**原因**：RA（Router Advertisement）未正确接收
**修复**：`netsh interface ipv6 set address "以太网" automatic` + 重启接口

### 案例 3：MTU 黑洞
**症状**：ping6 通，但 TCP 连接超时
**原因**：中间链路 MTU < 1500，但 ICMPv6 Packet Too Big 被防火墙阻断
**修复**：降低 MTU 到 1400，或放行 ICMPv6 Type 2（Packet Too Big）
