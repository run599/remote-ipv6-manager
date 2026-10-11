// ═══════════════════════════════════════════════════════════════════════════
// tools.go —— 受管端工具的"人话"入口
//
// 解决三个实际问题（都是真用过之后才显出来的）：
//
// ① **MCP 工具怎么发**：底层是 `mcp call <hwid> <tool> '{json}'`，但你得先知道
//    工具名、还得手写合法 JSON。这里加两条更好用的：
//      r6mctl tools                         列出可用工具**及其参数**
//      r6mctl tool <名> key=value ...       自动组 JSON（数字/布尔会按类型还原）
//
// ② **普通命令怎么跟工具调用区分**：这是最容易混的地方，所以把三类**显式分开**：
//      · 控制面（管服务端状态）  agents / task / artifact / file / screen ...
//      · 受管端命令（在受管端上跑）exec / powershell / ps / kill / shot
//      · 原始兜底（要什么给什么）api <M> <P> / mcp call <hwid> <tool> [json]
//    `exec` 就是"在受管端执行一条普通命令"——它本质是 execute 工具，
//    但你不该为了跑条命令去记 `{"command": ...}` 这种形状。
//
// ③ **默认目标机**：只有一台在线时不该每次都敲 hwid。
// ═══════════════════════════════════════════════════════════════════════════

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ── 工具参数表 ──────────────────────────────────────────────────────────────
//
// 这份表是**按插件自身 tools/list 的声明核对过的**（不是猜的）。
// 为什么要内置一份：服务端只中继 tools/call，不暴露 tools/list，
// 所以命令行侧想知道"这个工具要什么参数"只能自己带一份。
// 插件升级后如果 arg 名变了，这里会失效 —— 届时 `tools` 输出的说明能帮你判断。
type toolSpec struct {
	Name  string
	Desc  string
	Args  []string // 必填
	Opts  []string // 可选（含默认值说明）
	Usage string   // 例子
}

var toolCatalog = []toolSpec{
	{"list_processes", "列出进程（可搜索/排序）", nil,
		[]string{"search=模糊匹配", "sort_by=name|pid|mem(默认mem)", "limit=默认100"},
		`r6mctl ps --search chrome --sort mem --limit 20`},
	{"kill_process", "结束进程（按 PID 或名称）", []string{"pid 或 name"}, nil,
		`r6mctl kill 1234    /    r6mctl kill --name notepad.exe`},
	{"process_info", "查看单个进程详情", []string{"pid 或 name"}, nil,
		`r6mctl tool process_info pid=1234`},
	{"execute", "执行系统命令并返回输出", []string{"command"}, []string{"timeout=默认30秒", "cwd=工作目录"},
		`r6mctl exec "ipconfig /all"`},
	{"powershell", "执行 PowerShell 命令或脚本", []string{"command"}, nil,
		`r6mctl powershell "Get-Service | Where-Object Status -eq Running"`},
	{"screenshot", "截取主屏幕（返回图片）", nil, []string{"scale=1|2|4|8(默认2)", "format=bmp|png(默认bmp)"},
		`r6mctl shot --scale 4 --format png --out screen.png`},
	{"screen_info", "获取屏幕分辨率", nil, nil, `r6mctl tool screen_info`},
}

func findTool(name string) *toolSpec {
	for i := range toolCatalog {
		if toolCatalog[i].Name == name {
			return &toolCatalog[i]
		}
	}
	return nil
}

// ── 默认目标机解析 ──────────────────────────────────────────────────────────

func resolveAgent(c *Ctx, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if c.Agent != "" {
		return c.Agent
	}
	r, err := c.call("GET", "/api/agents", nil, nil)
	if err != nil {
		fail("无法获取受管端列表: %v", err)
	}
	type ag struct {
		HWID   string `json:"hwid"`
		Online bool   `json:"online"`
		User   string `json:"user"`
		OS     string `json:"os"`
	}
	var arr []ag
	if json.Unmarshal(r.Body, &arr) != nil {
		var wrap struct {
			Agents []ag `json:"agents"`
		}
		if json.Unmarshal(r.Body, &wrap) != nil {
			fail("受管端列表不是可识别的 JSON")
		}
		arr = wrap.Agents
	}
	var on []ag
	for _, a := range arr {
		if a.Online {
			on = append(on, a)
		}
	}
	switch len(on) {
	case 0:
		fail("没有在线的受管端（共 %d 台已登记）；先启动受管端，或用 `r6mctl agents` 查看", len(arr))
	case 1:
		return on[0].HWID
	default:
		var b strings.Builder
		for _, a := range on {
			fmt.Fprintf(&b, "\n    --agent %s   (%s / %s)", a.HWID, a.User, a.OS)
		}
		fail("有 %d 台在线，必须显式指定 --agent（不替你猜）：%s", len(on), b.String())
	}
	return ""
}


var reInt = regexp.MustCompile(`^-?\d+$`)

func kvToJSON(kv map[string]string, pos []string, posKey string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range kv {
		switch {
		case reInt.MatchString(v):
			n, _ := strconv.Atoi(v)
			out[k] = n
		case v == "true" || v == "false":
			out[k] = v == "true"
		default:
			// 允许 key="带空格的值"：把外层引号剥掉
			out[k] = strings.Trim(v, `"`)
		}
	}
	// 位置参数落到主参数名上（exec 的 command、kill 的 pid/name 等）
	if len(pos) > 0 && posKey != "" {
		joined := strings.Join(pos, " ")
		if reInt.MatchString(joined) {
			n, _ := strconv.Atoi(joined)
			out[posKey] = n
		} else {
			out[posKey] = joined
		}
	}
	return out
}

// runTool：组装 + 调用 + 原始 JSON 输出（不做内容裁剪，交由调用方决定怎么呈现）
func runTool(c *Ctx, hwid, name string, args map[string]interface{}) json.RawMessage {
	if findTool(name) == nil {
		// 未知工具不拦：插件可能提供目录之外的工具。只提示，不阻断。
		fmt.Fprintf(os.Stderr, "[r6mctl] 提示：%q 不在内置参数表里（表只是便利清单，不限制调用）\n", name)
	}
	raw, _ := json.Marshal(args)
	res, err := c.toolCall(hwid, name, raw)
	if err != nil {
		fail("%v", err)
	}
	return res
}

// toolText：把 MCP 结果里的文本抽出来（插件返回 {"content":[{"type":"text","text":...}]}）
func toolText(res json.RawMessage) string {
	var v struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
			Data string `json:"data"`
		} `json:"content"`
	}
	if json.Unmarshal(res, &v) == nil && len(v.Content) > 0 {
		if v.Content[0].Text != "" {
			return v.Content[0].Text
		}
		return v.Content[0].Data
	}
	return string(res)
}

// ── 命令实现 ───────────────────────────────────────────────────────────────

func cmdTools(c *Ctx, args []string) {
	kv, _ := parseKVFlags(args)
	if n := kv["name"]; n != "" {
		s := findTool(n)
		if s == nil {
			fail("内置参数表里没有 %q（表只是便利清单；仍可用 `r6mctl tool %s ...` 直调）", n, n)
		}
		emit(map[string]interface{}{"ok": true, "name": s.Name, "description": s.Desc,
			"required": s.Args, "optional": s.Opts, "example": s.Usage})
		return
	}
	var out []map[string]interface{}
	for _, s := range toolCatalog {
		out = append(out, map[string]interface{}{
			"name": s.Name, "description": s.Desc,
			"required": s.Args, "optional": s.Opts, "example": s.Usage,
		})
	}
	emit(map[string]interface{}{
		"ok": true, "tools": out,
		"note": "工具名由各插件自身的 tools/list 声明；本表是核对过的便利清单，不限制调用其他工具",
	})
}

// cmdTool：通用工具调用，参数用 key=value（自动类型还原）
func cmdTool(c *Ctx, args []string) {
	if len(args) < 1 {
		fail("用法: r6mctl tool <工具名> [key=value ...]   （不带参数时用 `r6mctl tools` 查名字与参数）")
	}
	name := args[0]
	kv, pos := parseKVFlags(args[1:])
	hwid := resolveAgent(c, kv["agent"])
	delete(kv, "agent")
	// 位置参数落到该工具的主参数上（能查到表就用表里的第一个必填名）
	posKey := ""
	if s := findTool(name); s != nil && len(s.Args) > 0 {
		posKey = strings.Fields(s.Args[0])[0]
	}
	res := runTool(c, hwid, name, kvToJSON(kv, pos, posKey))
	var v interface{}
	if json.Unmarshal(res, &v) == nil {
		emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": name, "result": v})
	} else {
		emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": name, "raw": string(res)})
	}
}

// cmdExecFamily：几条"人话"命令，本质都是 execute / powershell 工具的薄封装
func cmdExecFamily(c *Ctx, kind string, args []string) {
	kv, pos := parseKVFlags(args)
	hwid := resolveAgent(c, kv["agent"])
	delete(kv, "agent")

	// --out：把输出落盘（长输出别灌进上下文/终端）
	out := kv["out"]
	delete(kv, "out")

	// 命令本体：位置参数优先，其次 --command
	cmdStr := strings.Join(pos, " ")
	if cmdStr == "" {
		cmdStr = kv["command"]
		delete(kv, "command")
	}
	if cmdStr == "" {
		fail("用法: r6mctl %s <命令> [--timeout 30] [--cwd 目录] [--out 文件]", kind)
	}

	toolName := "execute"
	if kind == "powershell" || kind == "ps1" {
		toolName = "powershell"
	}
	body := map[string]interface{}{"command": cmdStr}
	for k, v := range kv {
		if reInt.MatchString(v) {
			n, _ := strconv.Atoi(v)
			body[k] = n
		} else {
			body[k] = v
		}
	}
	res := runTool(c, hwid, toolName, body)
	text := toolText(res)

	if out != "" {
		if err := os.WriteFile(out, []byte(text), 0644); err != nil {
			fail("写文件失败: %v", err)
		}
		emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": toolName,
			"command": cmdStr, "saved": out, "bytes": len(text)})
		return
	}
	emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": toolName,
		"command": cmdStr, "output": text})
}

// cmdPs / cmdKill / cmdShot / cmdScreenInfo：常用工具的短命令
func cmdPs(c *Ctx, args []string) {
	kv, pos := parseKVFlags(args)
	hwid := resolveAgent(c, kv["agent"])
	delete(kv, "agent")
	body := kvToJSON(kv, pos, "search")
	if s, ok := body["search"].(int); ok { // ps 1234 这种误用，退回字符串更安全
		body["search"] = strconv.Itoa(s)
	}
	res := runTool(c, hwid, "list_processes", body)
	emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": "list_processes",
		"output": toolText(res)})
}

func cmdKill(c *Ctx, args []string) {
	kv, pos := parseKVFlags(args)
	hwid := resolveAgent(c, kv["agent"])
	delete(kv, "agent")
	body := map[string]interface{}{}
	if n, ok := kv["name"]; ok {
		body["name"] = n
	}
	if p := strings.Join(pos, " "); p != "" {
		if reInt.MatchString(p) {
			n, _ := strconv.Atoi(p)
			body["pid"] = n
		} else {
			body["name"] = p
		}
	}
	if v, ok := kv["pid"]; ok {
		n, _ := strconv.Atoi(v)
		body["pid"] = n
	}
	if len(body) == 0 {
		fail("用法: r6mctl kill <PID>  或  r6mctl kill --name <进程名>")
	}
	res := runTool(c, hwid, "kill_process", body)
	emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": "kill_process",
		"output": toolText(res)})
}

var reDataURL = regexp.MustCompile(`^data:image/[a-z]+;base64,`)

// shotResult 对应 screen_capture 的 screenshot 返回体。
// 为什么优先用 image_base64 而不是 content[0].text：
// content 里的文本是**给人看**的，带 "[PNG base64]" 这类前缀，直接解码会得到乱码
// —— 我第一版就是这么写的，产出 54006 字节、魔数 3c d1 9b 6a… 的"假 PNG"，
// 而且命令还报 ok:true。结构化字段才是给程序用的。
type shotResult struct {
	ImageB64    string `json:"image_base64"`
	ImageFormat string `json:"image_format"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Bytes       int    `json:"bytes"`
	Content     []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// stripB64Label：剥掉人类可读前缀（"[PNG base64]" / "[BMP base64]" / data URL）
func stripB64Label(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "]"); i >= 0 && i < 40 {
		s = strings.TrimSpace(s[i+1:])
	}
	return reDataURL.ReplaceAllString(s, "")
}

// sniffImage：按魔数认格式。**解完必须验**：形状变了要立刻报错，
// 而不是默默写出一个坏文件（本次教训）。
func sniffImage(b []byte) string {
	switch {
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "png"
	case len(b) >= 2 && b[0] == 0x42 && b[1] == 0x4D:
		return "bmp"
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "jpeg"
	}
	return ""
}

func cmdShot(c *Ctx, args []string) {
	kv, _ := parseKVFlags(args) // 截图不吃位置参数（参数是 scale/format/out）
	hwid := resolveAgent(c, kv["agent"])
	delete(kv, "agent")
	out := kv["out"]
	delete(kv, "out")
	body := map[string]interface{}{}
	if v, ok := kv["scale"]; ok {
		n, _ := strconv.Atoi(v)
		body["scale"] = n
	}
	if v, ok := kv["format"]; ok {
		body["format"] = v
	}
	res := runTool(c, hwid, "screenshot", body)

	var sr shotResult
	_ = json.Unmarshal(res, &sr)
	b64 := sr.ImageB64
	if b64 == "" && len(sr.Content) > 0 {
		b64 = stripB64Label(sr.Content[0].Text)
	}
	if b64 == "" {
		fail("截图返回里没有可用的图片数据（形状可能变了；原始结果前 120 字：%.120s）", string(res))
	}

	if out == "" {
		// 不落盘时**只回元信息**：一帧 base64 动辄几百 KB，灌进终端/上下文毫无意义
		emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": "screenshot",
			"format": sr.ImageFormat, "width": sr.Width, "height": sr.Height,
			"base64_bytes": len(b64),
			"hint":         "要图请加 --out <文件>；直接把 base64 回给终端/模型没有意义"})
		return
	}

	raw := decodeB64(b64)
	kind := sniffImage(raw)
	if kind == "" {
		fail("解出来的不是图片（%d 字节，前 8 字节 % x）—— 返回形状可能变了，"+
			"别再假定 content[0].text 是纯 base64", len(raw), raw[:min(8, len(raw))])
	}
	// --out 没写扩展名时按真实格式补一个，避免存成误导性的名字
	if !strings.Contains(filepath.Base(out), ".") {
		out = out + "." + kind
	}
	if err := os.WriteFile(out, raw, 0644); err != nil {
		fail("写文件失败: %v", err)
	}
	emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": "screenshot",
		"saved": out, "format": kind, "width": sr.Width, "height": sr.Height,
		"bytes": len(raw)})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func cmdScreenInfo(c *Ctx, args []string) {
	kv, _ := parseKVFlags(args)
	hwid := resolveAgent(c, kv["agent"])
	res := runTool(c, hwid, "screen_info", map[string]interface{}{})
	emit(map[string]interface{}{"ok": true, "agent": hwid, "tool": "screen_info",
		"output": toolText(res)})
}

// cmdSchema —— **机器可读的能力清单**。
// 为什么这条对 AI 最重要：编排的前提是"能发现能力"。解析 help 散文易错、随文案变；
// 给一份结构化目录（名字/用途/参数/是否改状态/示例），它就能自己决定调什么、怎么填。
func cmdSchema() {
	type arg struct {
		Name     string `json:"name"`
		Required bool   `json:"required"`
		Desc     string `json:"desc"`
	}
	type cmd struct {
		Name    string   `json:"name"`
		Summary string   `json:"summary"`
		Usage   string   `json:"usage"`
		Mutates bool     `json:"mutates"`
		Needs   []string `json:"needs,omitempty"`
		Args    []arg    `json:"args,omitempty"`
		Example string   `json:"example"`
		Class   string   `json:"class"`
	}
	a := func(n string, r bool, d string) arg { return arg{n, r, d} }
	cat := []cmd{
		{"health", "服务端健康状态", "r6mctl health", false, nil, nil, "r6mctl health", "control"},
		{"agents", "列出受管端（裸 JSON 数组）", "r6mctl agents", false, nil, nil,
			"r6mctl agents --fields hwid,online,user", "control"},
		{"classes", "三类命令怎么区分", "r6mctl classes", false, nil, nil, "r6mctl classes", "control"},
		{"schema", "本清单", "r6mctl schema", false, nil, nil, "r6mctl schema", "control"},

		{"tools", "列出可用工具及参数", "r6mctl tools [--name X]", false, nil,
			[]arg{a("name", false, "只看某个工具")}, "r6mctl tools --name execute", "agent"},
		{"tool", "通用工具调用（参数 k=v）", "r6mctl tool <名> [k=v ...]", true, []string{"agent"},
			[]arg{a("<工具名>", true, "见 r6mctl tools"), a("k=v", false, "按参数表填")},
			"r6mctl tool list_processes search=chrome limit=10", "agent"},
		{"exec", "在受管端执行系统命令", "r6mctl exec <命令> [--timeout 30] [--cwd D] [--out F]",
			true, []string{"agent"}, []arg{a("<命令>", true, "命令原文")},
			`r6mctl exec "ipconfig /all"`, "agent"},
		{"powershell", "在受管端执行 PowerShell", "r6mctl powershell <命令>", true, []string{"agent"},
			[]arg{a("<命令>", true, "PowerShell 命令")},
			`r6mctl powershell "Get-Process | Select -First 5"`, "agent"},
		{"ps", "列进程", "r6mctl ps [--search X] [--sort mem|pid|name] [--limit N]", false,
			[]string{"agent"}, nil, "r6mctl ps --search chrome --limit 20 --fields output", "agent"},
		{"kill", "结束进程", "r6mctl kill <PID> | --name <名>", true, []string{"agent"},
			[]arg{a("<PID>", false, "进程号"), a("--name", false, "进程名")}, "r6mctl kill 1234", "agent"},
		{"shot", "截屏落盘（不给 --out 只回元信息）",
			"r6mctl shot [--scale 2] [--format png] --out <文件>", false, []string{"agent"},
			[]arg{a("--out", true, "落盘路径（强烈建议给，否则看不到图）")},
			"r6mctl shot --scale 4 --format png --out s.png", "agent"},
		{"screen-info", "屏幕分辨率", "r6mctl screen-info", false, []string{"agent"}, nil,
			"r6mctl screen-info", "agent"},


		{"file list", "列 filestore", "r6mctl file list", false, nil, nil,
			"r6mctl file list --fields name,size", "control"},
		{"file upload", "上传/发布到 filestore", "r6mctl file upload <本地路径> [--name 名]",
			true, nil, nil, "r6mctl file upload ./policy.reg", "control"},
		{"file deploy", "投放并**按类型应用**（可 dry-run）",
			"r6mctl file deploy --file-name X [--target-dir D] [--apply 类型] [--apply-args k=v] [--artifact] [--run] [--dry-run]",
			true, []string{"agent"}, []arg{a("--file-name", true, "filestore 里的文件名"),
				a("--apply", false, "none|exe|zip|reg|policy|ps1|bat|msi|cert|task|service|hosts|firewall|secedit"),
				a("--apply-args", false, "类型参数，如 name=MyTask / store=Root"),
				a("--artifact", false, "true=签发工件密钥并登记"),
				a("--run", false, "true=投放后启动"),
				a("--dry-run", false, "true=只报影响面，不改系统")},
			"r6mctl file deploy --file-name policy.reg --apply reg --dry-run", "control"},
		{"file batch", "**事务化**批量投放（全成或全回滚）",
			"r6mctl file batch --file <items.json> [--tx ID] [--allow-unrollbackable]", true,
			[]string{"agent"}, []arg{a("--file", true, "items JSON：数组或 {items:[...]}"),
				a("--allow-unrollbackable", false, "允许含 ps1/bat/msi（它们无法自动回滚）")},
			"r6mctl file batch --file items.json", "control"},
		{"file rollback", "回滚（按工件最近一次 / 按事务）",
			"r6mctl file rollback [--file-name X | --tx ID]", true, []string{"agent"}, nil,
			"r6mctl file rollback --tx tx-123", "control"},
		{"artifact list", "密钥 ↔ 文件/进程 映射", "r6mctl artifact list <hwid>", false,
			[]string{"agent"}, nil, "r6mctl artifact list <hwid>", "control"},
		{"screen start", "开始实时看屏", "r6mctl screen start <hwid> [--fps N]", true,
			[]string{"agent"}, nil, "r6mctl screen start <hwid> --fps 3", "control"},
		{"screen latest", "取最新帧（可落盘）", "r6mctl screen latest <hwid> [--out 文件]",
			false, []string{"agent"}, nil, "r6mctl screen latest <hwid> --out s.png", "control"},
		{"agent reauth", "吊销 per-agent 密钥以便重新登记", "r6mctl agent reauth <hwid>", true,
			nil, nil, "r6mctl agent reauth <hwid>", "control"},

		{"api", "直通任意端点（全覆盖兜底）", "r6mctl api <METHOD> <PATH> [JSON]", true, nil,
			[]arg{a("<METHOD>", true, "GET/POST"), a("<PATH>", true, "如 /api/health"),
				a("[JSON]", false, "请求体")}, "r6mctl api GET /api/health", "raw"},
		{"mcp call", "原始工具调用（不封装）", "r6mctl mcp call <hwid> <tool> [JSON]", true,
			[]string{"agent"}, nil, `r6mctl mcp call <hwid> list_processes '{"limit":5}'`, "raw"},
		{"mcp-serve", "以 MCP stdio 服务模式运行（供 AI 直接调用）", "r6mctl mcp-serve",
			false, nil, nil, "r6mctl --pass X mcp-serve", "raw"},
	}
	emit(map[string]interface{}{
		"ok":      true,
		"version": version,
		"output_contract": map[string]interface{}{
			"format":     "单行 JSON",
			"exit":       "失败退出码非 0",
			"error_code": "失败带 code：AUTH/BAD_ARGS/NOT_FOUND/CONFLICT/RATE_LIMITED/SERVER/HTTP_<n>/TIMEOUT/ERROR",
			"token_econ": "用 --fields a,b 裁剪；列表类务必裁，可省一个数量级 token",
			"discovery":  "先调 r6mctl schema 拿到本清单",
		},
		"globals": []map[string]interface{}{
			{"name": "--url", "desc": "服务端地址（或 R6M_URL）"},
			{"name": "--pass", "desc": "口令（或 R6M_PASS）；给一次后走缓存会话"},
			{"name": "--agent", "desc": "默认目标机；省略时唯一在线者自动选中，多台则报错（不替你猜）"},
			{"name": "--fields", "desc": "只输出这些字段（逗号分隔）"},
			{"name": "--quiet", "desc": "精简输出"},
			{"name": "--wait", "desc": "mcp call 等待上限（秒）"},
			{"name": "--artifact-key", "desc": "工件密钥（lock state / claim / pinunlock）"},
		},
		"commands": cat,
	})
}

// shellCmdClass：把"三类命令"讲清楚（`r6mctl classes`）
func shellCmdClass() {
	emit(map[string]interface{}{
		"ok": true,
		"classes": []map[string]interface{}{
			{"class": "控制面（管服务端状态，不碰受管端）",
				"commands": []string{"agents", "task ...", "artifact ...", "file ...",
					"screen start|stop|latest", "agent reauth", "integrity clear", "lock state"}},
			{"class": "受管端命令（真的在那台机器上执行）",
				"commands": []string{"exec <命令>", "powershell <命令>", "ps", "kill", "shot",
					"tool <工具名> k=v"},
				"note": "exec/powershell/ps/kill/shot 都是对 MCP 工具的薄封装，参数用 key=value"},
			{"class": "原始兜底（不封装，直接给形状）",
				"commands": []string{"api <METHOD> <PATH> [JSON]", "mcp call <hwid> <tool> [JSON]",
					"mcp result <id>"},
				"note": "新端点/新工具用它们，不必等 CLI 更新"},
		},
		"default_agent": "只给唯一在线的那台；多台时必须 --agent 显式指定（不替你猜）",
	})
}

// 让 sort 的引入有意义（工具表按名字排序输出时用）
func sortedToolNames() []string {
	var n []string
	for _, s := range toolCatalog {
		n = append(n, s.Name)
	}
	sort.Strings(n)
	return n
}

// cmdDesired —— 声明期望态。
//
// 就来取全量、按本地 ledger 对账、缺什么补什么，然后回报达成的 rev。
// 于是：离线机器回来自动收敛；投放到 N 台 = 改一次期望态；服务端重启也不丢。

// fetchDesiredItems 取当前期望态条目。
// add/rm 都必须"读-改-写" —— 直接整份覆盖会把别的来源（面板、插件一键装）加进来的条目冲掉。
func fetchDesiredItems(c *Ctx, hwid string) ([]interface{}, error) {
	r, err := c.call("GET", "/api/desired?hwid="+hwid, nil, nil)
	if err != nil {
		return nil, err
	}
	var o struct {
		Items []interface{} `json:"items"`
	}
	if json.Unmarshal(r.Body, &o) != nil {
		return nil, nil
	}
	if o.Items == nil {
		return []interface{}{}, nil
	}
	return o.Items, nil
}



// inferApply 从文件名推断 apply 类型 —— 期望态降门槛的最后一块。
//
// 为什么敢推断：apply 的种类其实由**文件形态**决定，而扩展名就写着形态。
// 但只推**无歧义**的那几种（比如 .txt 可能是 hosts 也可能是普通文本，
// 就不推，留给 --apply）；推不出一律 none（仅落地，不做任何动作）。
//
// 表的依据是客户端 KnownKinds() 的真实取值：
//   none exe/plugin zip reg policy ps1(bat/cmd) msi cert task service hosts firewall secedit
// 所以这里出现的 apply 名都确实被支持，不会推出一个服务端/客户端不认识的值。
func inferApply(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.HasSuffix(l, ".exe"), strings.HasSuffix(l, ".dll"):
		return "exe"
	case strings.HasSuffix(l, ".zip"):
		return "zip"
	case strings.HasSuffix(l, ".reg"):
		return "reg"
	case strings.HasSuffix(l, ".ps1"), strings.HasSuffix(l, ".bat"), strings.HasSuffix(l, ".cmd"):
		return "ps1"
	case strings.HasSuffix(l, ".msi"):
		return "msi"
	case strings.HasSuffix(l, ".cer"), strings.HasSuffix(l, ".crt"), strings.HasSuffix(l, ".pfx"):
		return "cert"
	case strings.HasSuffix(l, ".xml"):
		// 计划任务以 XML 导出（实测 filestore 里的 r6m-task.xml 就是这种）
		return "task"
	case strings.HasSuffix(l, ".inf"):
		// 安全模板是 .inf（secedit 的输入格式）
		return "secedit"
	}
	// hosts 没有稳定扩展名，按文件名里的关键字判断（实测样本 r6m-hosts.txt）
	if strings.Contains(l, "hosts") {
		return "hosts"
	}
	return "none"
}

func cmdDesired(c *Ctx, args []string) {
	sub := pick(args, 0, "get")
	kv, pos := parseKVFlags(args[1:])
	hwid := pick(pos, 0, kv["hwid"])
	if hwid == "" {
		hwid = resolveAgent(c, "")
	}
	switch sub {
	case "get":
		r, err := c.call("GET", "/api/desired?hwid="+hwid, nil, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "status":
		// 状态就在 /api/agents 里（服务端集成的运行事实），过滤出这一台
		r, err := c.call("GET", "/api/agents", nil, nil)
		if err != nil {
			fail("%v", err)
		}
		var arr []map[string]interface{}
		if json.Unmarshal(r.Body, &arr) != nil {
			var wrap struct {
				Agents []map[string]interface{} `json:"agents"`
			}
			if json.Unmarshal(r.Body, &wrap) != nil {
				fail("agents 返回无法解析")
			}
			arr = wrap.Agents
		}
		for _, a := range arr {
			if a["hwid"] == hwid {
				emit(map[string]interface{}{"ok": true, "agent": a})
				return
			}
		}
		failWith("NOT_FOUND", "没找到 %s", hwid)
	case "add", "pin":
		// 逐项添加。这是"期望态太难用"的直接解法：
		// 原来要手写 --items '[{...6 个字段...}]'，现在一条命令加一项，
		// 且 apply 由扩展名推断、其余字段可省（服务端只有 file_name 是必需的）。
		// 注意 pos[0] 是 hwid（cmdDesired 开头已把它取走），文件名在 pos[1] ——
		// 我第一版写成 pos[0]，结果把 hwid 当成了文件名加进期望态（实测抓到的）。
		if len(pos) < 2 {
			failWith("BAD_ARGS", "用法: r6mctl desired add <hwid> <file_name> [--dir D] [--apply K] [--args A] [--artifact] [--run] [--from S]；apply 不写就按扩展名推断(exe/zip/reg/ps1/msi/cert/xmltask/infsecedit/含hostshosts)，其余为 none")
		}
		name := pos[1]
		item := map[string]interface{}{"file_name": name}
		if v := kv["dir"]; v != "" {
			item["target_dir"] = v
		}
		// 没显式给 --apply 就按扩展名推断；给了就以用户为准
		// （用"键是否存在"区分"没给"和"给了 --apply none" —— 后者必须能压掉推断）
		ap, given := kv["apply"]
		if !given {
			ap = inferApply(name)
		}
		if ap != "" && ap != "none" {
			item["apply"] = ap
		}
		if v := kv["args"]; v != "" {
			item["apply_args"] = v
		}
		if v := kv["sha"]; v != "" {
			item["sha256"] = v
		}
		if v := kv["from"]; v != "" {
			item["from"] = v
		}
		// 裸 --artifact / --run 也认：用"键是否存在"判断，而不是值
		if _, ok := kv["artifact"]; ok {
			item["artifact"] = true
		}
		if _, ok := kv["run"]; ok {
			item["run"] = true
		}
		items, err := fetchDesiredItems(c, hwid)
		if err != nil {
			fail("%v", err)
		}
		replaced := false
		for i := range items {
			if mm, ok := items[i].(map[string]interface{}); ok && mm["file_name"] == name {
				items[i] = item
				replaced = true
				break
			}
		}
		if !replaced {
			items = append(items, item)
		}
		r, err := c.call("POST", "/api/desired",
			map[string]interface{}{"hwid": hwid, "items": items}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "rm":
		// 删一项（按 file_name），不必再整份覆盖
		if len(pos) < 2 {
			failWith("BAD_ARGS", "用法: r6mctl desired rm <hwid> <file_name>")
		}
		name := pos[1]
		items, err := fetchDesiredItems(c, hwid)
		if err != nil {
			fail("%v", err)
		}
		kept := []interface{}{}
		hit := false
		for _, it := range items {
			if mm, ok := it.(map[string]interface{}); ok && mm["file_name"] == name {
				hit = true
				continue
			}
			kept = append(kept, it)
		}
		if !hit {
			failWith("NOT_FOUND", "期望态里没有 %s", name)
		}
		r, err := c.call("POST", "/api/desired",
			map[string]interface{}{"hwid": hwid, "items": kept}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "set":
		// r6mctl desired set <hwid> --file items.json  |  --items '<json数组>'
		var raw string
		if f := kv["file"]; f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				fail("读 items 文件失败: %v", err)
			}
			raw = string(b)
		} else if v := kv["items"]; v != "" {
			raw = v
		} else if len(pos) > 1 {
			raw = strings.Join(pos[1:], " ")
		} else {
			failWith("BAD_ARGS", "用法: r6mctl desired set <hwid> --file items.json（每项与单件投放同构）")
		}
		var items []interface{}
		var probe interface{}
		if json.Unmarshal([]byte(raw), &probe) != nil {
			failWith("BAD_ARGS", "items 不是合法 JSON")
		}
		switch v := probe.(type) {
		case []interface{}:
			items = v
		case map[string]interface{}:
			arr, ok := v["items"].([]interface{})
			if !ok {
				failWith("BAD_ARGS", "JSON 对象里没有 items 数组")
			}
			items = arr
		default:
			failWith("BAD_ARGS", "items 既不是数组也不是含 items 的对象")
		}
		r, err := c.call("POST", "/api/desired",
			map[string]interface{}{"hwid": hwid, "items": items}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "history":
		// 收敛历史：每次 rev 的设定/达成时间、耗时、失败项
		r, err := c.call("GET", "/api/desired/history?hwid="+hwid, nil, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "clear":
		r, err := c.call("POST", "/api/desired",
			map[string]interface{}{"hwid": hwid, "items": []interface{}{}}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	default:
		failWith("BAD_ARGS", "未知 desired 子命令: %s（get|add|rm|set|status|history|clear）；常用 add/rm（逐项、字段可省，apply 默认 none）", sub)
	}
}
