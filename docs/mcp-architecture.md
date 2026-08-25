# MCP 插件架构

## 设计理念

传统远控使用 DLL 注入加载功能模块——杀毒软件高度警觉。本项目采用 **MCP（Model Context Protocol）进程模式**：每个功能模块是独立的命令行进程，通过 stdio JSON-RPC 2.0 通信。

```
杀毒软件视角：一个干净的网络客户端（RemoteClient.exe）
实际行为：    通过管道与多个 Python/Node 进程通信
```

## 通信协议

所有插件通过 **JSON-RPC 2.0** 通信（通过 stdin/stdout）：

### tools/list — 获取工具列表
```json
→ {"jsonrpc":"2.0","id":1,"method":"tools/list"}
← {"jsonrpc":"2.0","id":1,"result":{"tools":[
    {"name":"execute","description":"执行系统命令","inputSchema":{...}}
  ]}}
```

### tools/call — 调用工具
```json
→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"command":"whoami"}}}
← {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"DESKTOP-XXX\\user"}]}}
```

## 插件结构

```
plugins/
├── shell_exec/
│   ├── plugin.json          ← 插件元数据
│   └── shell_exec.py        ← 插件实现
├── process_list/
│   ├── plugin.json
│   └── process_list.py
└── screen_capture/
    ├── plugin.json
    └── screen_capture.py
```

### plugin.json 格式
```json
{
  "id": "shell_exec",
  "name": "远程 Shell",
  "version": "1.1.0",
  "command": "python shell_exec.py",
  "description": "执行系统命令并返回输出"
}
```

## 插件加载流程

1. 客户端启动 → `PluginLoader::scanPlugins()` 扫描 `plugins/` 目录
2. 读取每个 `plugin.json`，解析 command 字段
3. 按需启动进程（`CreateProcessW` + stdin/stdout 管道）
4. `buildToolMap()` 遍历所有插件，调用 `tools/list` 建立 工具名→插件ID 映射
5. 收到 `tools/call` → 查表找插件 → 转发 → 等待响应 → 回传

## 编写新插件

### Python 模板
```python
#!/usr/bin/env python3
import sys, json

def handle_request(req):
    method = req.get("method", "")
    params = req.get("params", {})
    
    if method == "tools/list":
        return {"tools": [
            {"name": "my_tool", "description": "工具描述",
             "inputSchema": {"type": "object", "properties": {...}}}
        ]}
    
    elif method == "tools/call":
        tool = params.get("name", "")
        args = params.get("arguments", {})
        if tool == "my_tool":
            # 实现逻辑
            return {"content": [{"type": "text", "text": "结果"}]}
    
    return {"error": "unknown method"}

# 主循环
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
for line in sys.stdin:
    req = json.loads(line.strip())
    resp = handle_request(req)
    resp["jsonrpc"] = "2.0"
    resp["id"] = req.get("id")
    print(json.dumps(resp, ensure_ascii=False), flush=True)
```

## 与传统 DLL 插件的对比

| | DLL 插件 | MCP 进程插件 |
|---|---|---|
| 隔离性 | 同一进程空间，崩溃影响整体 | 进程隔离，崩溃不影响 |
| 语言 | 仅 C/C++ | 任意语言（Python/Node/Go） |
| 安全性 | 杀毒高度警觉 | 杀毒视为普通进程 |
| 通信 | 函数调用 | stdio JSON-RPC |
| 部署 | 需编译 | 解释型语言直接运行 |
