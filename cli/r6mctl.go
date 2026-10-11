// ═══════════════════════════════════════════════════════════════════════════
// r6mctl —— 远程控制台的命令行客户端
//
// 设计目标（按"UI 用不了也能干完所有事"的要求）：
//   · **覆盖全部接口**：每个服务端端点都有具名子命令；另有一条 `api` 直通
//     （任意方法 + 任意路径 + 任意 JSON body），保证新加端点不用改 CLI 也能用。
//   · **AI 可驱动**：输出一律**单行 JSON**（{"ok":true,...} / {"ok":false,"error":...}），
//     失败时退出码非 0。不需要解析人类可读表格。
//   · **零依赖单二进制**：只用标准库，可交叉编译到路由器/被控机；`go build` 即可。
//   · **MCP stdio 服务模式**（`mcp-serve`）：把整条链路暴露成 MCP 工具，
//     AI 不必再拼 HTTP，直接 tools/call。
//
// 只用 UI 才行的（实时录屏预览、看图）不在这里强求 —— 但 `screen latest`
// 能取到最新帧的 base64，脚本/AI 侧仍可落盘看图。
// ═══════════════════════════════════════════════════════════════════════════

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const version = "1.0.0"

// ── 环境与配置 ──────────────────────────────────────────────────────────────

type Ctx struct {
	URL     string
	User    string
	Pass    string
	Verify  bool // 默认跳过证书校验（服务端是自签）
	Timeout time.Duration
	Wait    time.Duration // mcp call 等待结果的上限
	cookie  string
	cli     *http.Client

	// 用来在没有受管端 per-agent 密钥时也能操作这几个端点。
	ArtifactKey string
	ArtifactHWID string

	// 默认目标机：只给"唯一在线的那台"，多台时必须 --agent 显式指定。
	// （绝不替用户在多台里挑 —— 那是这类工具最危险的静默行为。）
	Agent string
}

func sessionFile() string {
	dir := os.Getenv("TEMP")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "r6mctl.session")
}

func loadCookie() string {
	b, err := os.ReadFile(sessionFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveCookie(c string) {
	if c == "" {
		return
	}
	_ = os.WriteFile(sessionFile(), []byte(c), 0600)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newCtx() *Ctx {
	to := 30 * time.Second
	if v := os.Getenv("R6M_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			to = time.Duration(n) * time.Second
		}
	}
	return &Ctx{
		URL:     strings.TrimRight(envOr("R6M_URL", "https://192.168.1.10:8443"), "/"),
		User:    envOr("R6M_USER", "admin"),
		Pass:    os.Getenv("R6M_PASS"),
		Verify:  os.Getenv("R6M_VERIFY_TLS") == "1",
		Timeout: to,
		Wait:    60 * time.Second,
		cookie:  loadCookie(),
		cli: &http.Client{
			Timeout: to,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// ── HTTP 底座 ───────────────────────────────────────────────────────────────

type Resp struct {
	Status int
	Body   []byte
}

func (c *Ctx) call(method, path string, body interface{}, extraHdr map[string]string) (*Resp, error) {
	return c.callN(method, path, body, extraHdr, 0)
}

func (c *Ctx) callN(method, path string, body interface{}, extraHdr map[string]string, depth int) (*Resp, error) {
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		case []byte:
			rdr = bytes.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			rdr = bytes.NewReader(b)
		}
	}
	url := path
	if !strings.HasPrefix(path, "http") {
		url = c.URL + path
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	// 工件密钥通道：带上就对工件鉴权的端点有效，对会话端点无害
	if c.ArtifactKey != "" {
		req.Header.Set("X-Artifact-Key", c.ArtifactKey)
		if c.ArtifactHWID != "" {
			req.Header.Set("X-Agent-HWID", c.ArtifactHWID)
		}
	}
	for k, v := range extraHdr {
		req.Header.Set(k, v)
	}
	resp, err := c.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if sc := resp.Header.Get("Set-Cookie"); sc != "" {
		// 取 "k=v" 部分
		c.cookie = strings.SplitN(sc, ";", 2)[0]
		saveCookie(c.cookie)
	}
	// 会话失效时自动重登 —— 但**只重试一次，且必须真的换到新会话**。
	// 原来是无条件递归重试，对"本来就不该用会话鉴权"的端点（例如
	if resp.StatusCode == 401 && depth == 0 && c.User != "" && c.Pass != "" && path != "/api/login" {
		old := c.cookie
		if e := c.login(); e == nil && c.cookie != "" && c.cookie != old {
			return c.callN(method, path, body, extraHdr, depth+1)
		}
	}
	return &Resp{Status: resp.StatusCode, Body: raw}, nil
}

func (c *Ctx) login() error {
	body := map[string]string{"user": c.User, "pass": c.Pass}
	r, err := c.call("POST", "/api/login", body, nil)
	if err != nil {
		return err
	}
	if r.Status != 200 {
		return fmt.Errorf("登录失败 HTTP %d: %s", r.Status, strings.TrimSpace(string(r.Body)))
	}
	return nil
}

// ensureAuth：没有会话就先登录（AI 全自动流程不允许"记得先手动登录"）
func (c *Ctx) ensureAuth() error {
	if c.cookie != "" {
		return nil
	}
	if c.User == "" || c.Pass == "" {
		return fmt.Errorf("缺少凭据：请给 --pass 或设 R6M_PASS 环境变量")
	}
	return c.login()
}

// uploadMultipart：走服务端自己的 /api/files/upload。
// 用它而不是 SFTP 的理由：AI 全自动场景里凭据越少越好 —— 只用手里的管理员会话，
// 不必把 SSH root 口令也交给脚本；文件名安全（basename + safeJoin）由服务端负责。
func (c *Ctx) uploadMultipart(path, field, filename string, data []byte) (*Resp, error) {
	return c.uploadMultipartN(path, field, filename, data, 0)
}

func (c *Ctx) uploadMultipartN(path, field, filename string, data []byte, depth int) (*Resp, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, err
	}
	_ = w.Close()
	req, err := http.NewRequest("POST", c.URL+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := c.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	// 会话过期时自动重登一次（与 call() 一致）。
	// 之前这里**没有**这段：服务端一重启，缓存的会话就失效，
	// 上传直接吃 401 —— 而其他命令却能自愈，表现为"只有上传莫名其妙失败"。
	if resp.StatusCode == 401 && depth == 0 && c.User != "" && c.Pass != "" {
		if e := c.login(); e == nil && c.cookie != "" {
			return c.uploadMultipartN(path, field, filename, data, depth+1)
		}
	}
	return &Resp{Status: resp.StatusCode, Body: raw}, nil
}

// ── 输出契约：单行 JSON ────────────────────────────────────────────────────
//
// 面向 AI 的三条约定：
//   · 单行 JSON，失败退出码非 0；
//   · 失败带 **code**（AUTH/BAD_ARGS/NOT_FOUND/CONFLICT/RATE_LIMITED/SERVER/…），
//     AI 靠它分支，不必去正则匹配人类可读的中文消息；
//   · --fields 裁剪输出：list 类返回动辄几十 KB，裁到关心的字段能省一个数量级 token。

var gFields []string // --fields a,b,c
var gQuiet bool      // --quiet

// project 按 --fields 裁剪（对象过滤键；数组逐元素裁）
func project(v interface{}) interface{} {
	if len(gFields) == 0 {
		return v
	}
	keep := map[string]bool{}
	for _, f := range gFields {
		keep[strings.TrimSpace(f)] = true
	}
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, vv := range x {
			if keep[k] || k == "ok" {
				out[k] = vv
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(x))
		for _, e := range x {
			out = append(out, project(e))
		}
		return out
	}
	return v
}

func emit(v interface{}) {
	b, _ := json.Marshal(project(v))
	fmt.Println(string(b))
}

// failWith：带错误码的失败
func failWith(code, format string, a ...interface{}) {
	b, _ := json.Marshal(project(map[string]interface{}{
		"ok": false, "code": code, "error": fmt.Sprintf(format, a...)}))
	fmt.Println(string(b))
	os.Exit(1)
}

func fail(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	code := "ERROR"
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "登录") ||
		strings.Contains(msg, "缺少凭据"):
		code = "AUTH"
	case strings.Contains(msg, "用法") || strings.Contains(msg, "缺少") ||
		strings.Contains(msg, "不是合法 JSON"):
		code = "BAD_ARGS"
	case strings.Contains(msg, "超时"):
		code = "TIMEOUT"
	case strings.Contains(msg, "不存在") || strings.Contains(msg, "找不到"):
		code = "NOT_FOUND"
	}
	failWith(code, "%s", msg)
}

func httpCode(status int) string {
	switch {
	case status == 401:
		return "AUTH"
	case status == 403:
		return "FORBIDDEN"
	case status == 404:
		return "NOT_FOUND"
	case status == 409:
		return "CONFLICT"
	case status == 429:
		return "RATE_LIMITED"
	case status >= 500:
		return "SERVER"
	case status >= 400:
		return "HTTP_" + strconv.Itoa(status)
	}
	return "OK"
}

// passJSON：把服务端响应原样转出去（能解析就直接嵌 JSON，不能解析就给原文）
func passJSON(r *Resp) {
	var v interface{}
	if json.Unmarshal(r.Body, &v) == nil {
		// 失败补 code：AI 用 code 分支，比匹配中文消息稳
		if m, ok := v.(map[string]interface{}); ok && r.Status >= 400 {
			if _, has := m["code"]; !has {
				m["code"] = httpCode(r.Status)
			}
		}
		emit(v)
		// 契约：失败必须给非 0 退出码。原来只看 ok 字段不设退出码，
		// AI/脚本拿 status 判断才是唯一可靠信号 —— 只能靠退出码时会误判成功。
		if r.Status >= 400 {
			os.Exit(1)
		}
		if m, ok := v.(map[string]interface{}); ok {
			if b, ok := m["ok"].(bool); ok && !b {
				os.Exit(1)
			}
		}
		return
	}
	emit(map[string]interface{}{
		"ok": r.Status == 200 && !strings.Contains(string(r.Body), "\"AGENT_OFFLINE\""),
		"code": func() string {
			if strings.Contains(string(r.Body), "AGENT_OFFLINE") {
				return "AGENT_OFFLINE"
			}
			return httpCode(r.Status)
		}(),
		"status": r.Status,
		"raw": strings.TrimSpace(string(r.Body)),
	})
	if r.Status >= 400 {
		os.Exit(1)
	}
}

// ── 工具中继：入队 + 轮询结果 ──────────────────────────────────────────────

type mcpCallResp struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
	Error     string `json:"error"`
}

func (c *Ctx) toolCall(hwid, name string, args json.RawMessage) (json.RawMessage, error) {
	// 即使没有参数也发空对象 {}：插件普遍直接写 arguments.get(...)，
	// 收到 None 会抛 "'NoneType' object has no attribute 'get'"（实测 list_processes 就是）。
	// 这是调用侧该兜住的兼容点，不该指望每个插件都判空。
	body := map[string]interface{}{"agent_hwid": hwid, "name": name, "arguments": map[string]interface{}{}}
	if len(args) > 0 {
		body["arguments"] = args
	}
	r, err := c.call("POST", "/api/mcp", body, nil)
	if err != nil {
		return nil, err
	}
	var cr mcpCallResp
	_ = json.Unmarshal(r.Body, &cr)
	if !cr.OK {
		msg := cr.Error
		if msg == "" {
			msg = strings.TrimSpace(string(r.Body))
		}
		return nil, fmt.Errorf("入队失败 HTTP %d: %s", r.Status, msg)
	}
	deadline := time.Now().Add(c.Wait)
	for time.Now().Before(deadline) {
		time.Sleep(700 * time.Millisecond)
		rr, err := c.call("GET", "/api/mcp/result?request_id="+cr.RequestID, nil, nil)
		if err != nil {
			continue
		}
		var out struct {
			OK     bool            `json:"ok"`
			Status string          `json:"status"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
			Code   string          `json:"code"`
		}
		if json.Unmarshal(rr.Body, &out) == nil {
			if out.OK && len(out.Result) > 0 {
				return out.Result, nil
			}
			// 原来只认成功分支，于是「受管端已离线」这类明确错误被静默吞掉，
			// 调用方要一直等到 deadline，最后只得到一句含糊的"等待结果超时"。
			// 这正是"点了没反应"在 CLI 侧的成因。
			if !out.OK && out.Status != "pending" && out.Error != "" {
				if out.Code != "" {
					return nil, fmt.Errorf("%s [%s]", out.Error, out.Code)
				}
				return nil, fmt.Errorf("%s", out.Error)
			}
		}
	}
	return nil, fmt.Errorf("等待结果超时（%s）；request_id=%s 可用 `mcp result %s` 稍后取回",
		c.Wait, cr.RequestID, cr.RequestID)
}

// ── 子命令实现 ─────────────────────────────────────────────────────────────

func pick(args []string, i int, def string) string {
	if i < len(args) {
		return args[i]
	}
	return def
}

// parseKVFlags：把 --k v 形式解析成 map（AI 侧拼参数比位置参数稳）
func parseKVFlags(args []string) (map[string]string, []string) {
	kv := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			k := strings.TrimPrefix(args[i], "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				kv[k] = args[i+1]
				i++
			} else {
				kv[k] = "true"
			}
			continue
		}
		pos = append(pos, args[i])
	}
	return kv, pos
}

func cmdLogin(c *Ctx) {
	if err := c.login(); err != nil {
		fail("%v", err)
	}
	emit(map[string]interface{}{"ok": true, "url": c.URL, "user": c.User,
		"session": sessionFile(), "note": "会话已缓存，后续命令免登录"})
}

func cmdAPI(c *Ctx, args []string) {
	// 直通：r6mctl api GET /api/agents [json-body]
	// 这条是"端点全覆盖"的兜底：新加接口不必等 CLI 更新
	if len(args) < 2 {
		fail("用法: r6mctl api <METHOD> <PATH> [json-body]")
	}
	method, path := strings.ToUpper(args[0]), args[1]
	var body interface{}
	if len(args) > 2 {
		body = strings.Join(args[2:], " ")
	}
	r, err := c.call(method, path, body, nil)
	if err != nil {
		fail("%v", err)
	}
	passJSON(r)
}

func cmdAgents(c *Ctx, args []string) {
	r, err := c.call("GET", "/api/agents", nil, nil)
	if err != nil {
		fail("%v", err)
	}
	passJSON(r)
}


func pick2(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func cmdArtifact(c *Ctx, args []string) {
	sub := pick(args, 0, "list")
	// args 为空时不能再切 args[1:] —— 那会 panic:
	// "slice bounds out of range [1:0]"。不带子命令本来就该等价于 list。
	rest := args
	if len(rest) > 0 {
		rest = rest[1:]
	}
	kv, pos := parseKVFlags(rest)
	switch sub {
	case "list":
		p := "/api/artifact/list"
		if h := pick(pos, 0, kv["hwid"]); h != "" {
			p += "?hwid=" + h
		}
		r, err := c.call("GET", p, nil, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "resolve", "register":
		p := "/api/artifact/" + sub
		if n := pick(pos, 0, kv["name"]); n != "" {
			p += "?name=" + n
		}
		var r *Resp
		var err error
		if sub == "register" {
			r, err = c.call("POST", p, kv, nil)
		} else {
			r, err = c.call("GET", p, nil, nil)
		}
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	default:
		fail("未知 artifact 子命令: %s（list|resolve|register）", sub)
	}
}

func cmdMCP(c *Ctx, args []string) {
	sub := pick(args, 0, "")
	switch sub {
	case "call":
		// r6mctl mcp call <hwid> <tool> [json-args]
		if len(args) < 3 {
			fail("用法: r6mctl mcp call <hwid> <tool> [json-args]")
		}
		hwid, tool := args[1], args[2]
		var raw json.RawMessage
		if len(args) > 3 {
			j := strings.Join(args[3:], " ")
			if !json.Valid([]byte(j)) {
				fail("工具参数不是合法 JSON: %s", j)
			}
			raw = json.RawMessage(j)
		}
		res, err := c.toolCall(hwid, tool, raw)
		if err != nil {
			fail("%v", err)
		}
		var v interface{}
		if json.Unmarshal(res, &v) == nil {
			emit(map[string]interface{}{"ok": true, "tool": tool, "hwid": hwid, "result": v})
		} else {
			emit(map[string]interface{}{"ok": true, "tool": tool, "hwid": hwid, "raw": string(res)})
		}
	case "result":
		if len(args) < 2 {
			fail("用法: r6mctl mcp result <request_id>")
		}
		r, err := c.call("GET", "/api/mcp/result?request_id="+args[1], nil, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "catalog", "tools":
		// 常用受管端工具清单（名字来自插件库；也可用 plugin list 查实际装载）
		// 这些名字是**核对过插件源码的 tools/list 声明**得来的，不是我猜的。
		// 上一版我照插件目录名编了一套（whoami/ipconfig/...），实测全部不存在
		// ——工具名 != 插件名，编出来的清单只会误导调用方。
		// 完整清单（客户端上报 58 个）由各插件的 tools/list 自报，
		// 这里只列仓库内置插件已验证可用的那些。
		emit(map[string]interface{}{"ok": true, "tools": []string{
			"list_processes", "kill_process", "process_info",   // plugins/process_list
			"screenshot", "screen_info",                         // plugins/screen_capture
			"execute", "powershell",                             // plugins/shell_exec
		}, "note": "工具名不等于插件名；完整清单由各插件自身的 tools/list 自报（客户端启动日志里是\"工具映射总数\"）"})
	default:
		fail("未知 mcp 子命令: %s（call|result|catalog）", sub)
	}
}

func cmdScreen(c *Ctx, args []string) {
	sub := pick(args, 0, "latest")
	kv, pos := parseKVFlags(args[1:])
	hwid := pick(pos, 0, kv["hwid"])
	switch sub {
	case "start":
		r, err := c.call("POST", "/api/screen/start",
			map[string]interface{}{"hwid": hwid, "fps": numOr(kv["fps"], 2)}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "stop":
		r, err := c.call("POST", "/api/screen/stop", map[string]interface{}{"hwid": hwid}, nil)
		if err != nil {
			fail("%v", err)
		}
		passJSON(r)
	case "latest":
		p := "/api/screen/latest"
		if hwid != "" {
			p += "?hwid=" + hwid
		}
		r, err := c.call("GET", p, nil, nil)
		if err != nil {
			fail("%v", err)
		}
		// 有 --out 就落盘（AI 侧拿到的是文件路径，避免把 base64 灌进上下文）
		if out := kv["out"]; out != "" {
			var o struct {
				Image string `json:"image"`
				Data  string `json:"data"`
			}
			_ = json.Unmarshal(r.Body, &o)
			b64 := o.Image
			if b64 == "" {
				b64 = o.Data
			}
			if b64 == "" {
				passJSON(r)
				return
			}
			if err := os.WriteFile(out, decodeB64(b64), 0644); err != nil {
				fail("写文件失败: %v", err)
			}
			emit(map[string]interface{}{"ok": true, "saved": out, "bytes": len(decodeB64(b64))})
			return
		}
		passJSON(r)
	default:
		fail("未知 screen 子命令: %s（start|stop|latest）", sub)
	}
}

func numOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

const b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// decodeB64：手写解码，避免为一行功能引入 import（也便于 AI 侧最小依赖）
func decodeB64(s string) []byte {
	s = strings.TrimSpace(s)
	var out []byte
	var acc uint32
	var n uint
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' || c == '\n' || c == '\r' {
			continue
		}
		v := strings.IndexByte(b64tab, c)
		if v < 0 {
			continue
		}
		acc = acc<<6 | uint32(v)
		n += 6
		if n >= 8 {
			n -= 8
			out = append(out, byte(acc>>n))
		}
	}
	return out
}

func cmdGeneric(c *Ctx, method, path string, args []string, useKV bool) {
	kv, pos := parseKVFlags(args)
	var body interface{}
	if useKV {
		if len(kv) > 0 {
			body = kv
		} else if len(pos) > 0 {
			body = strings.Join(pos, " ")
		}
	} else if len(pos) > 0 {
		body = strings.Join(pos, " ")
	}
	if p := pos; len(p) > 0 && strings.Contains(path, "%s") {
		path = fmt.Sprintf(path, p[0])
	}
	r, err := c.call(method, path, body, nil)
	if err != nil {
		fail("%v", err)
	}
	passJSON(r)
}

// ── MCP stdio 服务模式 ─────────────────────────────────────────────────────
//
// 为什么要它：控制台本来就是给 AI 用的（"投放 MCP 没指望人工操作"）。
// 有了这一层，AI 不必知道 HTTP 路径与鉴权细节，直接 tools/call 就能完成
// 查机器 / 发工具 / 建任务 / 取屏 / 调任意端点。

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func rpcResult(id json.RawMessage, result interface{}) {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
	fmt.Printf("%s\n", b)
	os.Stdout.Sync()
}

func rpcError(id json.RawMessage, code int, msg string) {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": json.RawMessage(id),
		"error": map[string]interface{}{"code": code, "message": msg}})
	fmt.Printf("%s\n", b)
	os.Stdout.Sync()
}

func toolResult(id json.RawMessage, text string, isErr bool) {
	rpcResult(id, map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
		"isError": isErr,
	})
}

var mcpTools = []map[string]interface{}{
	{
		"name":        "r6m_agents",
		"description": "列出所有受管端（含在线状态、hwid、任务待检查标记）",
		"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	},
	{
		"name":        "r6m_tool",
		"description": "在指定受管端上执行一个工具并等待结果（whoami/process_list/screenshot/shell_exec/ipconfig/gui_control 等）",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"hwid":      map[string]interface{}{"type": "string", "description": "目标受管端 hwid；省略则用唯一在线的那台"},
				"name":      map[string]interface{}{"type": "string", "description": "工具名"},
				"arguments": map[string]interface{}{"type": "object", "description": "工具参数对象"},
			},
			"required": []string{"name"},
		},
	},
	{
		"name":        "r6m_task",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":  map[string]interface{}{"type": "string"},
				"hwid":    map[string]interface{}{"type": "string"},
				"id":      map[string]interface{}{"type": "string"},
				"title":   map[string]interface{}{"type": "string"},
				"detail":  map[string]interface{}{"type": "string"},
				"check":   map[string]interface{}{"type": "string"},
				"minutes": map[string]interface{}{"type": "number"},
				"pin":     map[string]interface{}{"type": "string"},
			},
			"required": []string{"action"},
		},
	},
	{
		"name":        "r6m_artifact",
		"description": "外置工件：list（密钥↔文件/进程映射） / resolve（按文件名查该机原有密钥）",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action": map[string]interface{}{"type": "string"},
				"hwid":   map[string]interface{}{"type": "string"},
				"name":   map[string]interface{}{"type": "string"},
			},
			"required": []string{"action"},
		},
	},
	{
		"name":        "r6m_screen",
		"description": "实时看屏：start/stop/latest。latest 返回最新帧并可选落盘为 PNG/BMP 文件",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action": map[string]interface{}{"type": "string"},
				"hwid":   map[string]interface{}{"type": "string"},
				"fps":    map[string]interface{}{"type": "number"},
				"out":    map[string]interface{}{"type": "string", "description": "落盘的绝对路径"},
			},
			"required": []string{"action"},
		},
	},
	{
		"name":        "r6m_api",
		"description": "直通任意 REST 端点（方法+路径+可选 JSON body）。新接口不用等 CLI 更新即可调用，是「全覆盖」兜底",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"method": map[string]interface{}{"type": "string"},
				"path":   map[string]interface{}{"type": "string"},
				"body":   map[string]interface{}{"type": "object"},
			},
			"required": []string{"method", "path"},
		},
	},
}

// soloOnlineHWID：只有一台在线时自动选中，省掉 AI 反复查 hwid 的往返
func (c *Ctx) soloOnlineHWID() string {
	r, err := c.call("GET", "/api/agents", nil, nil)
	if err != nil {
		return ""
	}
	// 两种形状都接受，避免以后服务端改了包装又静默退化。
	type ag struct {
		HWID   string `json:"hwid"`
		Online bool   `json:"online"`
	}
	var arr []ag
	if json.Unmarshal(r.Body, &arr) != nil {
		var wrap struct {
			Agents []ag `json:"agents"`
		}
		if json.Unmarshal(r.Body, &wrap) != nil {
			return ""
		}
		arr = wrap.Agents
	}
	var found string
	n := 0
	for _, a := range arr {
		if a.Online {
			n++
			found = a.HWID
		}
	}
	if n == 1 {
		return found
	}
	return ""
}

func mcpServe(c *Ctx) {
	if err := c.ensureAuth(); err != nil {
		// 服务模式不退出：把错误留给每次工具调用回报，否则 MCP 宿主看到的是"进程秒退"
		fmt.Fprintf(os.Stderr, "[r6mctl] 登录失败（工具调用时会再报）: %v\n", err)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		// 兼容两种 stdio 帧：换行分隔的 JSON 与 LSP 风格的 Content-Length 头
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			continue
		}
		var req rpcReq
		if json.Unmarshal([]byte(line), &req) != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			rpcResult(req.ID, map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "r6mctl", "version": version},
			})
		case "notifications/initialized", "initialized":
			// 通知无需应答
		case "tools/list":
			rpcResult(req.ID, map[string]interface{}{"tools": mcpTools})
		case "ping":
			rpcResult(req.ID, map[string]interface{}{})
		case "tools/call":
			var p struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			}
			if json.Unmarshal(req.Params, &p) != nil {
				rpcError(req.ID, -32602, "bad params")
				continue
			}
			txt, isErr := runMCPTool(c, p.Name, p.Arguments)
			toolResult(req.ID, txt, isErr)
		default:
			rpcError(req.ID, -32601, "method not found: "+req.Method)
		}
	}
}

func jstr(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func runMCPTool(c *Ctx, name string, a map[string]interface{}) (string, bool) {
	if err := c.ensureAuth(); err != nil {
		return err.Error(), true
	}
	enc := func(v interface{}) string { b, _ := json.Marshal(v); return string(b) }
	switch name {
	case "r6m_agents":
		r, err := c.call("GET", "/api/agents", nil, nil)
		if err != nil {
			return err.Error(), true
		}
		return strings.TrimSpace(string(r.Body)), r.Status != 200

	case "r6m_tool":
		hwid := jstr(a, "hwid")
		if hwid == "" {
			hwid = c.soloOnlineHWID()
		}
		if hwid == "" {
			return "需要 hwid（有多台在线，或没有在线的受管端）；先调 r6m_agents", true
		}
		var raw json.RawMessage
		if v, ok := a["arguments"]; ok {
			raw, _ = json.Marshal(v)
		}
		res, err := c.toolCall(hwid, jstr(a, "name"), raw)
		if err != nil {
			return err.Error(), true
		}
		return string(res), false

	case "r6m_task":
		body := map[string]interface{}{}
		for k, v := range a {
			if k != "action" {
				body[k] = v
			}
		}
		act := jstr(a, "action")
		var path string
		var method string
		switch act {
		case "list":
			if h := jstr(a, "hwid"); h != "" {
				path += "?hwid=" + h
			}
		case "create":
		case "complete", "reset", "delete", "claim":
		case "unlock", "setpin", "pinunlock":
		default:
			return "未知 action: " + act, true
		}
		var bd interface{}
		if method == "POST" {
			bd = body
		}
		r, err := c.call(method, path, bd, nil)
		if err != nil {
			return err.Error(), true
		}
		return strings.TrimSpace(string(r.Body)), r.Status != 200

	case "r6m_artifact":
		act := jstr(a, "action")
		switch act {
		case "list":
			p := "/api/artifact/list"
			if h := jstr(a, "hwid"); h != "" {
				p += "?hwid=" + h
			}
			r, err := c.call("GET", p, nil, nil)
			if err != nil {
				return err.Error(), true
			}
			return strings.TrimSpace(string(r.Body)), r.Status != 200
		case "resolve":
			r, err := c.call("GET", "/api/artifact/resolve?name="+jstr(a, "name"), nil, nil)
			if err != nil {
				return err.Error(), true
			}
			return strings.TrimSpace(string(r.Body)), r.Status != 200
		}
		return "未知 action: " + act, true

	case "r6m_screen":
		act := jstr(a, "action")
		hwid := jstr(a, "hwid")
		switch act {
		case "start":
			r, err := c.call("POST", "/api/screen/start",
				map[string]interface{}{"hwid": hwid, "fps": numOr(jstr(a, "fps"), 2)}, nil)
			if err != nil {
				return err.Error(), true
			}
			return strings.TrimSpace(string(r.Body)), r.Status != 200
		case "stop":
			r, err := c.call("POST", "/api/screen/stop", map[string]interface{}{"hwid": hwid}, nil)
			if err != nil {
				return err.Error(), true
			}
			return strings.TrimSpace(string(r.Body)), r.Status != 200
		case "latest":
			p := "/api/screen/latest"
			if hwid != "" {
				p += "?hwid=" + hwid
			}
			r, err := c.call("GET", p, nil, nil)
			if err != nil {
				return err.Error(), true
			}
			if out := jstr(a, "out"); out != "" {
				var o struct {
					Image string `json:"image"`
					Data  string `json:"data"`
				}
				_ = json.Unmarshal(r.Body, &o)
				b64 := o.Image
				if b64 == "" {
					b64 = o.Data
				}
				if b64 == "" {
					return "服务端没有缓存帧（先 r6m_screen start，等几秒）", true
				}
				raw := decodeB64(b64)
				if err := os.WriteFile(out, raw, 0644); err != nil {
					return "写文件失败: " + err.Error(), true
				}
				return enc(map[string]interface{}{"ok": true, "saved": out, "bytes": len(raw)}), false
			}
			// 不回灌 base64（会撑爆上下文）：只回元信息 + 数据长度
			var v map[string]interface{}
			_ = json.Unmarshal(r.Body, &v)
			meta := map[string]interface{}{"ok": true}
			for k, vv := range v {
				if s, ok := vv.(string); ok && len(s) > 512 {
					meta[k+"_bytes"] = len(s)
					continue
				}
				meta[k] = vv
			}
			meta["hint"] = "需要图就给 out 参数落盘，再从文件读"
			return enc(meta), r.Status != 200
		}
		return "未知 action: " + act, true

	case "r6m_api":
		method := strings.ToUpper(jstr(a, "method"))
		path := jstr(a, "path")
		var body interface{}
		if v, ok := a["body"]; ok {
			body = v
		}
		r, err := c.call(method, path, body, nil)
		if err != nil {
			return err.Error(), true
		}
		return strings.TrimSpace(string(r.Body)), r.Status >= 400
	}
	return "未知工具: " + name, true
}

// ── 帮助与入口 ─────────────────────────────────────────────────────────────

func usage() {
	fmt.Print(`r6mctl ` + version + ` —— 远程控制台命令行客户端（UI 不可用时也能完成所有操作）

用法: r6mctl [全局选项] <命令> [参数]

全局选项:
  --url <URL>      服务端地址（或环境变量 R6M_URL，默认 ` + envOr("R6M_URL", "https://192.168.1.10:8443") + `）
  --user <USER>    登录用户（或 R6M_USER，默认 admin）
  --pass <PASS>    登录口令（或 R6M_PASS；不填则用已缓存会话）
  --wait <秒>      mcp call 等待结果上限（默认 60）
  --agent <HWID>   默认目标机；省略时"唯一在线的那台"自动选中，多台则报错要求显式指定
  --hwid <HWID>         配合 --artifact-key 使用

命令:
  login                                登录并缓存会话
  health | status                      服务端状态
  agents                               列出受管端
  api <METHOD> <PATH> [JSON]           直通任意端点（全覆盖兜底）
  schema                               机器可读能力清单（JSON，AI 编排用这个）
  classes                              说明"三类命令怎么区分"（建议先看）
  tools [--name X]                     列出可用工具及其参数
  tool <名> [k=v ...]                  通用工具调用（数字/布尔自动还原类型）

  ── 受管端命令（真的在那台机器上执行）──
  exec <命令> [--timeout 30] [--cwd D] 执行系统命令（= execute 工具）
  powershell <命令>                    执行 PowerShell
  ps [--search X] [--sort mem] [--limit N]
  kill <PID> | kill --name <进程名>
  shot [--scale 2] [--format png] --out 文件
  screen-info                          屏幕分辨率

  ── 原始兜底 ──
  mcp call <hwid> <tool> [JSON]        执行受管端工具并等结果
  mcp result <request_id>              取回异步结果
  mcp catalog                          常用受管端工具清单
  artifact list|resolve|register
  desired get|set|status <hwid>        声明期望态（受管端自动收敛，离线机器回来自动补齐）
  screen start|stop|latest [--out 文件]
  plugin list | plugin get <name>         列 filestore 里的可投放插件（会话鉴权）
  runtime                              列 filestore（含运行时包）
  file list                            列 filestore 文件
  file rollback --file-name <工件> [--agent H]  从最近备份回滚（注册表/策略/hosts/防火墙/证书/任务/服务）
  file rollback --tx <事务id> [--agent H]       按事务回滚整批
  file batch --file <items.json> [--tx ID]      事务化批量投放：**全成或全回滚**
      每项: {"file_name":"x.reg","target_dir":"C:\\x","apply":"reg"}
      含无法回滚的类型(ps1/bat/msi)会被**前置拒绝**，除非 --allow-unrollbackable true
  file upload <本地路径> [--name 名]    上传/发布到 filestore（同 publish，走 HTTP，不需 SSH）
  file deploy --file-name X [--apply 类型] [--dry-run]  投放并按类型应用
      apply 类型: none|exe|zip|reg|policy|ps1|bat|msi|cert|task|service|hosts|firewall|secedit
  agent reauth <hwid>
  integrity clear <hwid>
  mcp-serve                            以 MCP stdio 服务模式运行（供 AI 直接调用）

输出约定: 单行 JSON；失败时 ok=false 且退出码非 0，并带 code（便于分支）。

给 AI 用:
  r6mctl schema                          # 能力清单（命令/参数/是否改状态/示例）
  r6mctl agents --fields hwid,online     # 只取需要的字段，省 token
  r6mctl --pass X mcp-serve              # 以 MCP stdio 服务运行
`)
}

func main() {
	args := os.Args[1:]
	c := newCtx()

	// 全局选项（可出现在命令前）
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch args[0] {
		case "--url":
			if len(args) > 1 {
				c.URL = strings.TrimRight(args[1], "/")
				args = args[2:]
				continue
			}
		case "--user":
			if len(args) > 1 {
				c.User = args[1]
				args = args[2:]
				continue
			}
		case "--pass":
			if len(args) > 1 {
				c.Pass = args[1]
				args = args[2:]
				continue
			}
		case "--wait":
			if len(args) > 1 {
				if n, err := strconv.Atoi(args[1]); err == nil {
					c.Wait = time.Duration(n) * time.Second
				}
				args = args[2:]
				continue
			}
		case "--artifact-key":
			if len(args) > 1 {
				c.ArtifactKey = args[1]
				args = args[2:]
				continue
			}
		case "--hwid":
			if len(args) > 1 {
				c.ArtifactHWID = args[1]
				args = args[2:]
				continue
			}
		case "--agent":
			if len(args) > 1 {
				c.Agent = args[1]
				args = args[2:]
				continue
			}
		case "--fields":
			if len(args) > 1 {
				gFields = strings.Split(args[1], ",")
				args = args[2:]
				continue
			}
		case "--quiet":
			gQuiet = true
			args = args[1:]
			continue
		}
		break
	}

	if len(args) == 0 {
		usage()
		return
	}
	// 全局选项**预扫描**：--artifact-key/--hwid/--agent 无论写在命令前还是后都生效。
	// 原来只在命令前解析，于是最常见的写法
	// 会失败（还报"缺工件密钥"，看起来像参数没传对）。
	{
		var kept []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			take := func(dst *string) bool {
				if i+1 < len(args) {
					*dst = args[i+1]
					i++
					return true
				}
				return false
			}
			switch a {
			case "--artifact-key":
				if take(&c.ArtifactKey) {
					continue
				}
			case "--hwid":
				if take(&c.ArtifactHWID) {
					continue
				}
			case "--agent":
				if take(&c.Agent) {
					continue
				}
			case "--fields":
				// 必须也在这里预扫描：写成 `r6mctl agents --fields hwid,online`
				// （选项在命令之后）时，前端那个"只吃命令前选项"的循环根本看不到它，
				// 于是 --fields 被当成位置参数丢掉、裁剪静默失效。
				var v string
				if take(&v) {
					gFields = strings.Split(v, ",")
					continue
				}
			case "--quiet":
				gQuiet = true
				continue
			}
			kept = append(kept, a)
		}
		args = kept
	}
	if len(args) == 0 {
		usage()
		return
	}

	cmd := args[0]
	rest := args[1:]

	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		usage()
		return
	}
	if cmd == "mcp-serve" {
		mcpServe(c)
		return
	}
	if cmd == "login" {
		cmdLogin(c)
		return
	}
	if err := c.ensureAuth(); err != nil {
		fail("%v", err)
	}

	switch cmd {
	case "health":
		cmdGeneric(c, "GET", "/api/health", rest, false)
	case "status":
		cmdGeneric(c, "GET", "/api/status", rest, false)
	case "agents":
		cmdAgents(c, rest)
	case "api":
		cmdAPI(c, rest)
	case "mcp":
		cmdMCP(c, rest)
	case "classes":
		shellCmdClass()
	case "schema":
		cmdSchema()
	case "tools":
		cmdTools(c, rest)
	case "tool":
		cmdTool(c, rest)
	case "exec", "run":
		cmdExecFamily(c, "exec", rest)
	case "powershell", "ps1":
		cmdExecFamily(c, "powershell", rest)
	case "ps":
		cmdPs(c, rest)
	case "kill":
		cmdKill(c, rest)
	case "shot":
		cmdShot(c, rest)
	case "screen-info":
		cmdScreenInfo(c, rest)
	case "artifact":
		cmdArtifact(c, rest)
	case "desired":
		cmdDesired(c, rest)
	case "screen":
		cmdScreen(c, rest)
	case "plugin":
		// 密钥的受管端能拉自己的插件包），管理端会话打过去只会得到 401 ——
		// 我第一版就是这么写的，实测 {"error":"unauthorized"}。
		// 管理端真正需要的是"filestore 里有哪些插件可投放"，那个走会话可用的
		// /api/files/list?path=<dir>。
		sub := pick(rest, 0, "list")
		if sub == "get" {
			// /api/files/get 同样是受管端鉴权（受管端拉自己的插件包用）；
			// 管理端读文件内容要走 /api/files/download。
			cmdGeneric(c, "GET", "/api/files/download?name=plugins/"+pick(rest, 1, "")+"/plugin.json", nil, false)
		} else {
			cmdGeneric(c, "GET", "/api/files/list?path=plugins", nil, false)
		}
	case "runtime":
		// 同理：/api/runtime 是给受管端拉嵌入式解释器用的（受管端鉴权）。
		// 管理端看"有没有运行时包可投放"应列 filestore 根目录。
		cmdGeneric(c, "GET", "/api/files/list", nil, false)
	case "file":
		sub := pick(rest, 0, "list")
		switch sub {
		case "list":
			cmdGeneric(c, "GET", "/api/files/list", rest[1:], false)
		case "deploy":
			// r6mctl file deploy --file-name X [--target-dir D] [--artifact] [--run]
			//                   [--agent <hwid>] [--verify-ms 20000]
			//
			// 字段名必须是**下划线**（服务端结构体是 agent_hwid/file_name/target_dir）：
			// 直接传 --file-name 会变成 "file-name"，服务端解不出来，
			// 表现为"接口返回 ok 但什么都没发生"。
			kv3, _ := parseKVFlags(rest[1:])
			hwid := kv3["agent"]
			if hwid == "" {
				hwid = c.Agent
			}
			if hwid == "" {
				hwid = resolveAgent(c, "")
			}
			fn := kv3["file-name"]
			if fn == "" {
				fn = kv3["name"]
			}
			if fn == "" {
				fail("用法: r6mctl file deploy --file-name <文件名> [--target-dir D] [--artifact] [--run]")
			}
			body := map[string]interface{}{
				"agent_hwid": hwid, "file_name": fn, "target_dir": kv3["target-dir"],
			}
			wantArtifact := kv3["artifact"] == "true" || kv3["artifact"] == "1" || kv3["artifact"] == ""
			if _, ok := kv3["artifact"]; ok {
				wantArtifact = kv3["artifact"] != "false" && kv3["artifact"] != "0"
			}
			body["artifact"] = wantArtifact
			body["run"] = kv3["run"] == "true" || kv3["run"] == "1"
			// 落地之后怎么应用：注册表/策略/脚本/证书/任务/服务/hosts/防火墙/安全策略…
			// 默认 none（仅落地），保持既有行为不变。
			if v, ok := kv3["apply"]; ok {
				body["apply"] = v
			}
			if v, ok := kv3["apply-args"]; ok {
				body["apply_args"] = v
			}
			body["dry_run"] = kv3["dry-run"] == "true" || kv3["dry-run"] == "1"
			r, err := c.call("POST", "/api/files/deploy", body, nil)
			if err != nil {
				fail("%v", err)
			}
			if r.Status >= 400 {
				passJSON(r)
				os.Exit(1)
			}
			// 外置工件要等它签发密钥+登记，所以这里回读一次，把
			// key ↔ 文件/进程 的映射直接给出来 —— 一条命令闭环。
			ms := 0
			if v, ok := kv3["verify-ms"]; ok {
				ms, _ = strconv.Atoi(v)
			} else if body["run"] == true || wantArtifact {
				ms = 25000
			}
			var disp struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(r.Body, &disp)
			out := map[string]interface{}{"ok": true, "dispatched": true, "agent": hwid,
				"file_name": fn, "artifact": wantArtifact, "run": body["run"],
				"request_id": disp.RequestID}

			// 先取一次命令结果：投放失败（例如目录非法、下载失败）时，
			// 受管端会在这里给出**真实原因**。不取的话只能靠 artifact 是否出现来猜。
			if disp.RequestID != "" {
				for i := 0; i < 12; i++ {
					time.Sleep(1500 * time.Millisecond)
					rr, e2 := c.call("GET", "/api/mcp/result?request_id="+disp.RequestID, nil, nil)
					if e2 != nil {
						continue
					}
					var cr struct {
						OK     bool            `json:"ok"`
						Result json.RawMessage `json:"result"`
					}
					if json.Unmarshal(rr.Body, &cr) != nil || !cr.OK || len(cr.Result) == 0 {
						continue
					}
					var res struct {
						OK          bool   `json:"ok"`
						Error       string `json:"error"`
						ArtifactKey string `json:"artifact_key"`
						ApplyDetail string `json:"apply_detail"`
						ApplyError  string `json:"apply_error"`
					}
					if json.Unmarshal(cr.Result, &res) == nil {
						out["deploy_ok"] = res.OK
						if res.Error != "" {
							out["deploy_error"] = res.Error
						}
						if res.ArtifactKey != "" {
							out["key_prefix"] = res.ArtifactKey[:8] + "…"
						}
						// 应用动作的详情必须回给调用方：管理端要能确认"到底改了什么"
						if res.ApplyDetail != "" {
							out["apply_detail"] = res.ApplyDetail
						}
						if res.ApplyError != "" {
							out["apply_error"] = res.ApplyError
						}
					}
					break
				}
			}
			if ms > 0 {
				deadline := time.Now().Add(time.Duration(ms) * time.Millisecond)
				for time.Now().Before(deadline) {
					time.Sleep(2 * time.Second)
					rr, e2 := c.call("GET", "/api/artifact/list?hwid="+hwid, nil, nil)
					if e2 != nil {
						continue
					}
					var al struct {
						Artifacts []map[string]interface{} `json:"artifacts"`
					}
					if json.Unmarshal(rr.Body, &al) != nil {
						continue
					}
					for _, a := range al.Artifacts {
						if a["name"] == fn {
							out["artifact_registered"] = a
							if k, ok := a["key"].(string); ok {
								out["key_prefix"] = k
							}
						}
					}
					if _, ok := out["artifact_registered"]; ok {
						break
					}
				}
				if _, ok := out["artifact_registered"]; !ok {
					out["artifact_registered"] = nil
					out["note"] = "等待登记超时：看受管端日志里的「工件」相关行（登记失败会明确写原因）"
				}
			}
			emit(out)
		case "download":
			cmdGeneric(c, "GET", "/api/files/download?name="+pick(rest, 1, ""), nil, false)
		case "delete":
			// 服务端从查询串取 name（不是 body）—— 传 body 会得到 {"error":"invalid name"}
			cmdGeneric(c, "POST", "/api/files/delete?name="+pick(rest, 1, ""), nil, false)
		case "batch":
			// 事务化批量投放：全成或全回滚。
			//    r6mctl file batch --file items.json   |  r6mctl file batch '<json数组>'
			// JSON 可以是裸数组，也可以是 {"items":[...]}；每项与单件投放同构。
			kv5, pos5 := parseKVFlags(rest[1:])
			hwid := kv5["agent"]
			if hwid == "" {
				hwid = resolveAgent(c, "")
			}
			var raw string
			if f := kv5["file"]; f != "" {
				b, err := os.ReadFile(f)
				if err != nil {
					fail("读批次文件失败: %v", err)
				}
				raw = string(b)
			} else if len(pos5) > 0 {
				raw = strings.Join(pos5, " ")
			} else {
				fail("用法: r6mctl file batch --file <items.json>（或直接给 JSON）")
			}
			var probe interface{}
			if json.Unmarshal([]byte(raw), &probe) != nil {
				fail("批次内容不是合法 JSON")
			}
			var items []interface{}
			switch v := probe.(type) {
			case []interface{}:
				items = v
			case map[string]interface{}:
				arr, ok := v["items"].([]interface{})
				if !ok {
					fail("JSON 对象里没有 items 数组")
				}
				items = arr
			default:
				fail("批次内容既不是数组也不是含 items 的对象")
			}
			body := map[string]interface{}{"agent_hwid": hwid, "items": items}
			if t := kv5["tx"]; t != "" {
				body["tx"] = t
			}
			if kv5["allow-unrollbackable"] == "true" || kv5["allow-unrollbackable"] == "1" {
				body["allow_unrollbackable"] = true
			}
			r, err := c.call("POST", "/api/files/deploy_batch", body, nil)
			if err != nil {
				fail("%v", err)
			}
			if r.Status >= 400 {
				passJSON(r)
				os.Exit(1)
			}
			var db struct {
				Tx        string `json:"tx"`
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(r.Body, &db)
			out := map[string]interface{}{"ok": true, "dispatched": true, "agent": hwid,
				"tx": db.Tx, "items": len(items), "request_id": db.RequestID}
			// 事务可能耗时（多项应用），等久一点
			deadline := time.Now().Add(180 * time.Second)
			if v, ok := kv5["wait"]; ok {
				if n, e := strconv.Atoi(v); e == nil {
					deadline = time.Now().Add(time.Duration(n) * time.Second)
				}
			}
			for db.RequestID != "" && time.Now().Before(deadline) {
				time.Sleep(2 * time.Second)
				rr, e2 := c.call("GET", "/api/mcp/result?request_id="+db.RequestID, nil, nil)
				if e2 != nil {
					continue
				}
				var cr struct {
					OK     bool            `json:"ok"`
					Result json.RawMessage `json:"result"`
				}
				if json.Unmarshal(rr.Body, &cr) != nil || !cr.OK || len(cr.Result) == 0 {
					continue
				}
				var res map[string]interface{}
				if json.Unmarshal(cr.Result, &res) == nil {
					out["batch_ok"] = res["ok"]
					if b, ok := res["batch"]; ok {
						out["batch"] = b
					}
					if e, ok := res["error"]; ok && e != "" {
						out["error"] = e
					}
				}
				break
			}
			emit(out)
			if bo, ok := out["batch_ok"].(bool); ok && !bo {
				os.Exit(1)
			}

		case "rollback":
			// 从最近一次备份还原（注册表/策略/hosts/防火墙/证书/任务/服务…）
			kv4, _ := parseKVFlags(rest[1:])
			hwid := kv4["agent"]
			if hwid == "" {
				hwid = resolveAgent(c, "")
			}
			// 按事务回滚整批（--tx），或按工件回滚最近一次（--file-name）
			if tx := kv4["tx"]; tx != "" {
				r, err := c.call("POST", "/api/files/rollback_tx",
					map[string]interface{}{"agent_hwid": hwid, "tx": tx}, nil)
				if err != nil {
					fail("%v", err)
				}
				if r.Status >= 400 {
					passJSON(r)
					os.Exit(1)
				}
				var rb struct {
					RequestID string `json:"request_id"`
				}
				_ = json.Unmarshal(r.Body, &rb)
				out := map[string]interface{}{"ok": true, "dispatched": true, "agent": hwid,
					"tx": tx, "request_id": rb.RequestID}
				for i := 0; i < 20 && rb.RequestID != ""; i++ {
					time.Sleep(1500 * time.Millisecond)
					rr, e2 := c.call("GET", "/api/mcp/result?request_id="+rb.RequestID, nil, nil)
					if e2 != nil {
						continue
					}
					var cr struct {
						OK     bool            `json:"ok"`
						Result json.RawMessage `json:"result"`
					}
					if json.Unmarshal(rr.Body, &cr) != nil || !cr.OK || len(cr.Result) == 0 {
						continue
					}
					var res struct {
						OK          bool   `json:"ok"`
						Error       string `json:"error"`
						ApplyDetail string `json:"apply_detail"`
					}
					if json.Unmarshal(cr.Result, &res) == nil {
						out["rollback_ok"] = res.OK
						if res.Error != "" {
							out["rollback_error"] = res.Error
						}
						if res.ApplyDetail != "" {
							out["detail"] = res.ApplyDetail
						}
					}
					break
				}
				emit(out)
				if b, ok := out["rollback_ok"].(bool); ok && !b {
					os.Exit(1)
				}
				return
			}
			fn := kv4["file-name"]
			if fn == "" {
				fail("用法: r6mctl file rollback --file-name <工件名> | --tx <事务id> [--agent <hwid>]")
			}
			r, err := c.call("POST", "/api/files/rollback",
				map[string]interface{}{"agent_hwid": hwid, "file_name": fn}, nil)
			if err != nil {
				fail("%v", err)
			}
			if r.Status >= 400 {
				passJSON(r)
				os.Exit(1)
			}
			var rb struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(r.Body, &rb)
			out := map[string]interface{}{"ok": true, "dispatched": true, "agent": hwid,
				"file_name": fn, "request_id": rb.RequestID}
			if rb.RequestID != "" {
				for i := 0; i < 15; i++ {
					time.Sleep(1500 * time.Millisecond)
					rr, e2 := c.call("GET", "/api/mcp/result?request_id="+rb.RequestID, nil, nil)
					if e2 != nil {
						continue
					}
					var cr struct {
						OK     bool            `json:"ok"`
						Result json.RawMessage `json:"result"`
					}
					if json.Unmarshal(rr.Body, &cr) != nil || !cr.OK || len(cr.Result) == 0 {
						continue
					}
					var res struct {
						OK          bool   `json:"ok"`
						Error       string `json:"error"`
						ApplyDetail string `json:"apply_detail"`
					}
					if json.Unmarshal(cr.Result, &res) == nil {
						out["rollback_ok"] = res.OK
						if res.Error != "" {
							out["rollback_error"] = res.Error
						}
						if res.ApplyDetail != "" {
							out["detail"] = res.ApplyDetail
						}
					}
					break
				}
			}
			emit(out)

		case "upload", "publish":
			// r6mctl file upload <本地路径> [--name 远端文件名]
			// publish 是同一个动作的别名：把本地产物推进 filestore，好让受管端投放。
			// （原来这一步只有 tools/publish_filestore.py 在做，走 SSH+SFTP；
			//   现在 HTTP 链路也能做，且只需管理员会话。）
			kv2, pos2 := parseKVFlags(rest[1:])
			local := pick(pos2, 0, kv2["local"])
			if local == "" {
				fail("用法: r6mctl file upload <本地路径> [--name 远端文件名]")
			}
			data, err := os.ReadFile(local)
			if err != nil {
				fail("读本地文件失败: %v", err)
			}
			name := kv2["name"]
			if name == "" {
				name = filepath.Base(local)
			}
			r, err := c.uploadMultipart("/api/files/upload", "file", name, data)
			if err != nil {
				fail("%v", err)
			}
			if r.Status >= 400 {
				passJSON(r)
				os.Exit(1)
			}
			emit(map[string]interface{}{"ok": true, "uploaded": name,
				"bytes": len(data), "local": local,
				"note": "已进 filestore，可被 deploy_file 投放"})
		default:
			cmdGeneric(c, "GET", "/api/files", rest, false)
		}
	case "agent":
		if pick(rest, 0, "") == "reauth" {
			cmdGeneric(c, "POST", "/api/agent/reauth?hwid="+pick(rest, 1, ""), []string{}, true)
		} else {
			fail("未知 agent 子命令: %s（reauth）", pick(rest, 0, ""))
		}
	case "integrity":
		if pick(rest, 0, "") == "clear" {
			cmdGeneric(c, "POST", "/api/integrity/clear?hwid="+pick(rest, 1, ""), []string{}, true)
		} else {
			fail("未知 integrity 子命令: %s（clear）", pick(rest, 0, ""))
		}
	default:
		fail("未知命令: %s（用 r6mctl help 看用法）", cmd)
	}
}

func mapToArgs(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, "--"+k, v)
	}
	return out
}
