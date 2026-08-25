# Remote IPv6 Manager

**基于 IPv6 自愈的远程管理工具** —— 无需公网 IPv4，直连全球任意 IPv6 设备。

> 大量用户的 IPv6 处于"残疾"状态：运营商分配了地址但配置有误、防火墙策略不对、DNS64/NAT64 不通。
> 本工具自动诊断并修复 IPv6 连接，让你的设备真正"可达"。

## ✨ 核心特性

### 🌐 IPv6 自愈（核心卖点）
```
检测 → 诊断 → 修复 → 验证
```
- 自动检测 IPv6 连接状态（链路本地 / 全局 / DNS）
- 诊断常见问题：地址未配置、默认网关缺失、MTU 异常、防火墙阻断
- 一键修复：`netsh` 重置接口、调整防火墙策略、刷新路由
- 修复后自动验证连通性（ping6 → TCP 连接 → HTTP 探测）

### 🔌 绕过 NAT 的远程管理
- **IPv6 直连**：不需要公网 IPv4、不需要端口映射、不需要 frp/ngrok
- **MCP 插件架构**：进程隔离 + stdio JSON-RPC，干净可扩展
- **跨平台服务端**：Go 编写，支持 Linux/Windows/macOS
- **轻量客户端**：C++17 纯原生，无第三方依赖，单 exe 部署

### 🧩 MCP 插件系统
```
┌─────────────┐    stdin/stdout    ┌──────────────┐
│   Shell      │ ◄── JSON-RPC ──► │   Plugin     │
│   Plugin     │                   │   Process    │
├─────────────┤                   ├──────────────┤
│ shell_exec   │                   │ Python/Node  │
│ process_list │                   │ 独立进程     │
│ screen_shot  │                   │              │
└─────────────┘                   └──────────────┘
```

| 插件 | 功能 | 实现 |
|------|------|------|
| `shell_exec` | 远程命令执行（cmd/PowerShell） | Python |
| `process_list` | 进程管理（列表/搜索/结束） | Python |
| `screen_capture` | 远程截屏（base64 BMP） | Python + ctypes |
| `file_manager` | 文件浏览/读写/删除 | Python |

## 📁 项目结构

```
remote-ipv6-manager/
├── server/                  ← Go 服务端
│   ├── main.go              ← HTTP API + Agent 管理 + MCP 中继
│   └── go.mod
├── client/                  ← C++17 客户端
│   ├── src/
│   │   ├── main.cpp         ← 入口
│   │   ├── StubCore.cpp     ← 核心：连接/轮询/插件转发
│   │   ├── NetworkFix.cpp   ← IPv6 自愈核心（诊断+修复+验证）
│   │   ├── PluginLoader.cpp ← MCP 插件管理（扫描/启动/通信）
│   │   └── Logger.cpp       ← 日志
│   ├── include/
│   └── CMakeLists.txt
├── plugins/                 ← MCP 插件
│   ├── shell_exec/
│   ├── process_list/
│   └── screen_capture/
└── docs/                    ← 技术文档
    ├── ipv6-repair.md       ← IPv6 自愈原理
    ├── mcp-architecture.md  ← 插件架构
    └── network-fix.md       ← NetworkFix 实现细节
```

## 🚀 快速开始

### 编译服务端（需要 Go 1.21+）
```bash
cd server
go build -o c2-server .
./c2-server serve --port 8080
```

### 编译客户端（需要 CMake + MSVC）
```bash
cd client
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
# 输出: client/build/Release/RemoteClient.exe
```

### 部署插件
1. 将 `plugins/` 目录放到服务端的 `filestore/plugins/` 下
2. 客户端启动时自动从服务端同步缺失的插件
3. 自动下载嵌入式 Python 运行时（首次启动）

### 运行
```bash
# 服务端
./c2-server serve --port 8080

# 客户端（设置环境变量指向你的服务端 IPv6 地址）
set R6M_SERVER=http://[your-server-ipv6]:8080
RemoteClient.exe
```

## 🏗️ 架构设计

```
┌──────────────┐         IPv6         ┌──────────────┐
│   Client     │ ◄──────────────────► │   Server     │
│  (C++17)     │    HTTP polling      │  (Go)        │
│              │                      │              │
│  ┌────────┐  │   ┌──────────────┐   │  ┌────────┐  │
│  │Network │  │   │ MCP Plugin   │   │  │ Agent  │  │
│  │ Fix    │  │   │ Loader       │   │  │Registry│  │
│  └────────┘  │   │              │   │  └────────┘  │
│              │   │ ┌──────────┐ │   │              │
│              │   │ │ shell    │ │   │  ┌────────┐  │
│              │   │ │ process  │ │   │  │ Command│  │
│              │   │ │ screen   │ │   │  │ Queue  │  │
│              │   │ └──────────┘ │   │  └────────┘  │
│              │   └──────────────┘   │              │
└──────────────┘                      └──────────────┘
```

## 🔧 IPv6 自愈流程

```
┌─────────────┐
│ 检测 IPv6    │ → ping6 网关 / 外网
├─────────────┤
│ 诊断问题     │ → 接口状态? 地址? 网关? MTU? 防火墙?
├─────────────┤
│ 修复        │ → netsh 重置 / 防火墙策略 / 路由修复
├─────────────┤
│ 验证        │ → ping6 → TCP → HTTP 逐级验证
├─────────────┤
│ 报告        │ → 返回修复结果和当前状态
└─────────────┘
```

详见 [docs/ipv6-repair.md](docs/ipv6-repair.md)

## 📝 技术亮点

1. **IPv6 自愈**：覆盖 90% 的家庭 IPv6 残疾场景（地址未分配、网关缺失、MTU 不匹配、防火墙阻断）
2. **MCP 插件架构**：每个插件是独立进程，崩溃不影响主程序；通过 stdio JSON-RPC 通信，语言无关
3. **零依赖部署**：服务端单二进制，客户端单 exe + 自动下载嵌入式 Python
4. **IPv6 直连**：绕过 NAT，不需要 frp/ngrok/DDNS，延迟更低
5. **轻量高效**：C++ 客户端内存 < 5MB，心跳间隔可配置

## 📄 License

MIT License

## 🤝 Contributing

欢迎贡献代码、报告 Bug、提出新插件想法！

## ⚠️ 免责声明

本工具仅用于合法的远程设备管理和网络诊断。请遵守当地法律法规。
