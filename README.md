# Remote IPv6 Manager

**基于 IPv6 自愈的远程管理工具** —— 自动诊断并修复"残疾"的 IPv6 网络，让设备真正可达。

## 为什么需要它

中国家庭宽带的 IPv6 普及率已超过 70%，但"分配了地址却连不上"的残疾状态极其普遍：路由器 SLAAC 配置错误、防火墙策略挡住 ICMPv6、默认网关缺失、MTU 不匹配……传统远程工具（RustDesk、ToDesk 等）在这种设备上**直接歇菜**，只能靠人工排查 netsh 命令。

本项目的核心思路：**把 IPv6 修复做成远程连接的前置自动环节**。

```
检测 → 诊断 → 修复 → 验证
```

客户端启动时自动执行 NetworkFix：

1. **检测**：ping6 网关 / 外网目标，判定 v6 链路健康度
2. **诊断**：接口状态？全局地址？默认网关？MTU？防火墙策略？
3. **修复**：netsh 重置接口、补路由、调整防火墙策略
4. **验证**：ping6 → TCP → HTTP 逐级验证连通性

修复完成后才建立管理通道。**市面上的远程工具要么"教你手动修"（激活指南、论坛帖），要么"绕开它"（DDNS/组网）——没有把修复做进客户端本身的。**

## ✨ 特性

### 🌐 IPv6 自愈（核心）
- 覆盖两类最常见的 v6 残疾：**无全球地址**（RA/SLAAC 未下发 → 用 C2 的 /64 前缀
  与 link-local 主机标识补一个地址）与**默认网关缺失**（补 ::/0，优先用 link-local 网关）
- 修复后做一次 ping6 验证并写日志（失败不阻断，Stub 会继续重试）
- ⚠️ **未实现**：MTU 检查、防火墙 ICMPv6 规则、DHCPv6 重取、`ipv6 reset`；
  详见 `docs/network-fix.md` 的「明确未实现的能力」
- IPv6 公网直连被控端，无需公网 IPv4、无需端口映射、无需 frp/ngrok

### 🔐 安全设计
- **全链路 TLS**（1.2+）+ **发凭据前校验指纹**：客户端先做一次无凭据的
  `GET /api/health` 探测并校验证书 SHA-256 指纹，通过后才发送引导密钥；
  明文 `http://` 直接拒绝启动（不降级）
- **per-agent 密钥**：引导密钥仅用于**首次登记**一个全新 hwid；已登记的 hwid
  只接受它自己那把密钥（`409 already enrolled`），杜绝"持有引导密钥即可冒名接管"
- **密钥持久化**：客户端把 per-agent 密钥用 DPAPI（机器范围）存到
  `%ProgramData%\RemoteIPv6Manager\agent.key`，重启后无需再用引导密钥
- **完整性自检（AntiHook）三态**：一致 / 确认被篡改 / 无法验证。
  只有"确认被篡改"才熔断；"无法验证"（模块未加载、转发导出）只告警，
  且支持 `POST /api/integrity/clear?hwid=...` 由运维解除熔断
- 服务端：登录指数退避限速、会话过期、路径穿越防护、请求体与队列上限、
  未知 hwid 拒绝入队、结果归属校验（他机 request_id 无法伪造）
- 密钥不经命令行传递：提权时把有效配置写入受限 DACL 的临时文件
  （`--agent-key` 已移除，密钥对同机任何进程都不可见）

### 🧩 MCP 插件架构
- 插件为独立进程（Python），崩溃不影响主程序
- 通过 stdio JSON-RPC 通信，语言无关
- 客户端启动时自动从服务端同步插件与运行时，零手工部署

内置插件：`shell_exec`（远程命令）、`process_list`（进程管理）、`screen_capture`（截屏）

## 📁 项目结构

```
remote-ipv6-manager/
├── server/                  ← Go 服务端（调度中心）
│   ├── main.go              ← HTTPS API + Agent 管理 + MCP 中继
│   ├── cert.go              ← TLS 证书生成与指纹管理
│   └── go.mod
├── client/                  ← C++17 客户端（被控端）
│   ├── src/
│   │   ├── main.cpp         ← 入口（UAC 提权、日志）
│   │   ├── StubCore.cpp     ← 核心：TLS 连接/轮询/插件转发/密钥管理
│   │   ├── AntiHook.cpp     ← 完整性自检（检测/上报/熔断）
│   │   ├── NetworkFix.cpp   ← IPv6 自愈核心
│   │   ├── PluginLoader.cpp ← MCP 插件管理
│   │   └── Logger.cpp       ← 日志
│   └── CMakeLists.txt
├── plugins/                 ← MCP 插件（Python）
├── panel/                   ← Qt/QML 管理面板
└── docs/                    ← 技术文档
    ├── ipv6-repair.md       ← IPv6 自愈原理
    ├── mcp-architecture.md  ← 插件架构
    └── network-fix.md       ← NetworkFix 实现细节
```

## 🚀 快速开始

### 服务端（需要 Go 1.21+，支持交叉编译）

```bash
cd server
go build -o c2-server .
./c2-server serve --port 8443            # 首次启动自动生成 TLS 证书并打印指纹
```

生产环境（Linux ARM64 示例，全静态链接）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o c2-server-arm64
```

服务端启动后日志会输出：
- **证书 SHA-256 指纹**（编译客户端时需要）
- **agent.key**（引导密钥，部署新客户端时需要）

### 客户端（需要 CMake + MSVC）

```bash
cd client
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
# 输出: client/build/Release/RemoteClient.exe
```

### 客户端配置与部署

在 exe 同目录放一个 `r6m.ini`（双击即跑，无需命令行）：

```ini
server=https://[2001:db8:YOUR-SERVER-IPv6-HERE]:8443
agent_key=<服务端 agent.key 的内容>
```

也支持环境变量 `R6M_SERVER` / `R6M_AGENT_KEY`，以及命令行参数 `--server`。
优先级：命令行（仅 `--server`）> 环境变量 > `r6m.ini`。

> `--agent-key` 已于 2026-10-07 移除：命令行对本机任何进程可读
> （WMI / 任务管理器 / EDR 日志），密钥放在那里等于公开。
> 密钥请走 `r6m.ini` 或 `R6M_AGENT_KEY`；UAC 提权时程序会自动把有效配置
> 写入受限 DACL 的临时文件并让提升后的进程读取（读完即删）。

首次运行流程（全自动）：
1. UAC 提权（IPv6 路由修复需要）
2. IPv6 自愈检测与修复
3. 注册换取本机独立密钥
4. 下载 Python 运行时 + 插件
5. 心跳 + 轮询开始工作

### 管理方式

**CLI**（服务端自带）：

```bash
c2-server agent list                                          # 在线 Agent
c2-server mcp call <hwid> execute '{"command":"whoami"}'      # 远程命令
c2-server mcp call <hwid> list_processes '{}'                 # 进程列表
```

**面板**：Qt/QML 图形界面（Agent 列表 / Shell / MCP 工具 / 文件 / 截屏），见 `panel/` 目录。

```bash
cd panel
cmake -B build -G "Visual Studio 17 2022" -A x64   # 需要 Qt6 (Quick/QuickControls2/Network)
cmake --build build --config Release
```

> 构建的是 QML 版（`src/qml_main.cpp`）。`src/` 下另有一套 QtWidgets 实现
> （MainWindow/AgentListWidget/... 约 1100 行），与 QML 版功能重复且各自定义了
> `main()`，默认**不参与构建**（`-DPANEL_LEGACY_WIDGETS=ON` 可单独构建）。
>
> 已知边界：文件页的「上传/下载/删除」需要被控端的 `file_manager` 插件，
> 本仓库只附带 `shell_exec` / `process_list` / `screen_capture` 三个插件，
> 因此这三个按钮会明确提示"未实现"而不是静默无响应。

## 🛠 运维端点（面板/CLI 之外）

| 端点 | 用途 |
|---|---|
| `GET /api/health` | 无凭据探针，供客户端在发密钥前校验 TLS 指纹 |
| `POST /api/integrity/clear?hwid=<hwid>` | 运维确认排查完毕后解除该 agent 的熔断（下次 poll 下发） |
| `POST /api/agent/rekey?hwid=<hwid>` | 吊销某 hwid 的 per-agent 密钥，允许其用引导密钥重新登记（换机/重装场景） |

三个端点都需要面板会话（`c2session`）认证（`/api/health` 除外）。

## 🔧 工作原理

```
┌──────────────┐      HTTPS (TLS, pinned)      ┌──────────────┐
│   Client     │ ◄───────────────────────────► │    Server    │
│  (C++17)     │   注册→换per-agent密钥→轮询    │     (Go)     │
│              │                               │              │
│ NetworkFix   │   注册后自动同步               │  CommandQueue│
│ AntiHook     │   ◄── Python runtime ──       │  AgentRegistry│
│ PluginLoader │   ◄── MCP plugins ─────       │  MCP relay   │
└──────┬───────┘                               └──────┬───────┘
       │ stdio JSON-RPC                               │
┌──────▼───────┐                               ┌──────▼───────┐
│ MCP Plugins  │                               │ CLI / Panel  │
└──────────────┘                               └──────────────┘
```

## ⚠️ 免责声明

本工具仅用于**你拥有或获得明确授权**的设备管理与网络诊断（例如：自己的家庭服务器、实验室虚拟机、授权范围内的运维）。

- 请勿部署到未经授权的第三方设备
- 使用本工具产生的一切后果由使用者自行承担

## 📄 License

MIT
