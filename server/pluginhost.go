package main

// ═══════════════════════════════════════════════════════════════════════════
// server 侧插件宿主（P3）
//
// 第二步（本文件）加了四件，核心是**把 I/O 结构改成能同时处理两个方向**：
//
//   ③ 能力白名单    plugin.json 里 host_caps 没声明的能力，一律拒绝并记审计
//   ④ 审计          每次 host/call 都留痕（谁、什么时候、要什么、给没给）
//
// 但反向通道意味着**插件会主动往 stdout 写一条"请求"**，而宿主可能正在等
// 某次调用的响应 —— 两个方向的报文混在同一个管道里。
// 所以改成：**一个读线程 + pending 表 + 反向分发**。这是唯一正确的结构；
// 用"读一行猜一行"的写法必然会把请求当响应吃掉（那会表现为"调用莫名超时"）。
//
// 还没做（诚实列出）：崩溃自动重启（现在只标记 failed + 原因）、
// deploy_file 等真正需要内核配合的能力（返回"尚未实现"而不是假装成功）、
// 以及每插件令牌的**校验**（已集成，但目前走 stdio 不需要它）。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pluginCallTimeout = 30 * time.Second // 单次工具调用超时
	pluginHandshake   = 5 * time.Second  // 握手超时（与 agent 侧一致）
	auditRingMax      = 200              // 审计只留最近 N 条
)

// pluginRoute 插件声明要接管的 HTTP 路径。
// **auth 必须由插件声明**，不能由内核猜：同一个 /api/task/ 前缀下，
// claim/pinunlock 是受管端调的（agent 密钥），list/create 是管理端调的（管理员会话），
// 两者不是一回事。内核若统一按一种鉴权临时授权，就等于给其中一方开了维护通道。
type pluginRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   string `json:"auth"` // agent | session | none
}

type PluginRunState struct {
	ID        string   `json:"id"`
	Routes    []string `json:"routes,omitempty"`
	State     string   `json:"state"` // loaded | failed
	Err       string   `json:"err,omitempty"`
	Caps      []string `json:"caps,omitempty"`
	Tools     []string `json:"tools,omitempty"`
	ToolCount int      `json:"tool_count"`
	PID       int      `json:"pid,omitempty"`
	Calls     int      `json:"calls"`
	StartedMs int64    `json:"started_ms,omitempty"`
}

type auditEntry struct {
	Ms     int64  `json:"ms"`
	Plugin string `json:"plugin"`
	Cap    string `json:"cap"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type rpcResp struct {
	result json.RawMessage
	err    error
}

type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	if b.buf.Len() > b.max {
		s := b.buf.String()
		b.buf.Reset()
		b.buf.WriteString(s[len(s)-b.max:])
	}
	return len(p), nil
}

func (b *boundedBuffer) Tail(n int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.TrimSpace(b.buf.String())
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}

type srvPlugin struct {
	id      string
	dir     string
	command string
	caps    map[string]bool
	routes  []pluginRoute

	proc   *exec.Cmd
	stdin  io.WriteCloser
	wrMu   sync.Mutex // 保护 stdin 的并发写
	nextID int64
	mu     sync.Mutex
	pend   map[int64]chan rpcResp
	state  PluginRunState
	errBuf *boundedBuffer
	host   *PluginHost
}

type PluginHost struct {
	pluginRoot string
	stateDir   string
	pyExe      string

	mu      sync.Mutex
	plugins map[string]*srvPlugin
	order   []string

	auditMu sync.Mutex
	audit   []auditEntry

	kvMu sync.Mutex
	kv   map[string]string // host/call state_* 的落点（P2 会把它做成权威并下发受管端）
}

func NewPluginHost(pluginRoot string, stateDir string) *PluginHost {
	py := "python3"
	if _, err := exec.LookPath(py); err != nil {
		py = "python"
	}
	return &PluginHost{pluginRoot: pluginRoot, pyExe: py, stateDir: stateDir,
		plugins: map[string]*srvPlugin{}, kv: map[string]string{}}
}

func (h *PluginHost) auditLog(plugin, cap string, ok bool, detail string) {
	e := auditEntry{Ms: time.Now().UnixMilli(), Plugin: plugin, Cap: cap, OK: ok, Detail: detail}
	h.auditMu.Lock()
	h.audit = append(h.audit, e)
	if len(h.audit) > auditRingMax {
		h.audit = h.audit[len(h.audit)-auditRingMax:]
	}
	h.auditMu.Unlock()
	if ok {
		log.Printf("[PluginHost][audit] %s host/call %s 允许", plugin, cap)
	} else {
		log.Printf("[PluginHost][audit] %s host/call %s **拒绝**: %s", plugin, cap, detail)
	}
}

func (h *PluginHost) Audit() []auditEntry {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	out := make([]auditEntry, len(h.audit))
	copy(out, h.audit)
	return out
}

// Start 扫描 side=server 的插件并逐个拉起 + 握手。side=agent 的插件不在这里管：
// 它们要读本机进程/屏幕，在服务端拉起它们毫无意义，还会制造"看着加载了其实做不了"的假象。
func (h *PluginHost) Start() {
	entries, err := os.ReadDir(h.pluginRoot)
	if err != nil {
		log.Printf("[PluginHost] 插件目录读不到 %s: %v", h.pluginRoot, err)
		return
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(h.pluginRoot, e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "plugin.json"))
		if err != nil {
			continue
		}
		var meta map[string]interface{}
		if json.Unmarshal(raw, &meta) != nil {
			continue
		}
		if side, _ := meta["side"].(string); side != "server" {
			continue
		}
		cmdStr, _ := meta["command"].(string)
		var routes []pluginRoute
		if arr, ok := meta["routes"].([]interface{}); ok {
			for _, rv := range arr {
				m, ok := rv.(map[string]interface{})
				if !ok {
					continue
				}
				path, _ := m["path"].(string)
				if path == "" || !strings.HasPrefix(path, "/") {
					continue // 只接绝对路径；相对路径会造成"注册到哪"的歧义
				}
				method, _ := m["method"].(string)
				auth, _ := m["auth"].(string)
				if method == "" {
					method = "POST"
				}
				routes = append(routes, pluginRoute{
					Method: strings.ToUpper(method), Path: path, Auth: auth})
			}
		}
		caps := map[string]bool{}
		if arr, ok := meta["host_caps"].([]interface{}); ok {
			for _, c := range arr {
				if s, ok := c.(string); ok && s != "" {
					caps[s] = true
				}
			}
		}
		p := &srvPlugin{
			id: e.Name(), dir: dir, command: cmdStr, caps: caps, routes: routes,
			errBuf: &boundedBuffer{max: 4096},
			pend:   map[int64]chan rpcResp{},
			state:  PluginRunState{ID: e.Name(), State: "starting"},
			host:   h,
		}
		for c := range caps {
			p.state.Caps = append(p.state.Caps, c)
		}
		for _, rt := range routes {
			p.state.Routes = append(p.state.Routes, rt.Method+" "+rt.Path+" ("+rt.Auth+")")
		}
		h.mu.Lock()
		h.plugins[p.id] = p
		h.order = append(h.order, p.id)
		h.mu.Unlock()
		h.spawnAndHandshake(p)
		n++
	}
	if n == 0 {
		log.Printf("[PluginHost] 没有 side=server 的插件（扫了 %d 个目录）", len(entries))
		return
	}
	for _, id := range h.order {
		st := h.StateFor(id)
		if st.State == "loaded" {
			log.Printf("[PluginHost] %s 已加载 pid=%d 工具=%d 能力=%v", id, st.PID, st.ToolCount, st.Caps)
		} else {
			// 失败必须出声，并且带原因
			log.Printf("[PluginHost] %s 加载失败: %s", id, st.Err)
		}
	}
}

func (h *PluginHost) spawnAndHandshake(p *srvPlugin) {
	if strings.TrimSpace(p.command) == "" {
		p.state.State = "failed"
		p.state.Err = "plugin.json 里没有 command（side=server 的插件必须给出可执行命令）"
		return
	}
	parts := strings.Fields(p.command)
	bin, args := h.pyExe, parts
	switch parts[0] {
	case "python", "python3":
		args = parts[1:]
	default:
		bin, args = parts[0], parts[1:]
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = p.dir
	// 每插件令牌：插件**永远不接触管理员口令**。
	// 现在插件走 stdio，用不到它；这是为"插件以后要调宿主 HTTP 面"准备的，
	// 而且是每插件独立、随机生成的 —— 不做"所有插件共用一把钥匙"。
	tok := make([]byte, 16)
	_, _ = rand.Read(tok)
	// 插件自己的状态目录：必须是**服务端的私有状态区**，不能放在 filestore 里 ——
	// filestore 的文件清单会被同步到受管端（插件状态跟着过去既没必要也不安全）。
	pdir := filepath.Join(h.stateDir, "plugins", p.id)
	_ = os.MkdirAll(pdir, 0755)
	cmd.Env = append(os.Environ(),
		"R6M_PLUGIN_ID="+p.id,
		"R6M_PLUGIN_TOKEN="+hex.EncodeToString(tok),
		"R6M_STATE_DIR="+pdir,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		p.state.State, p.state.Err = "failed", "拿不到 stdin 管道: "+err.Error()
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		p.state.State, p.state.Err = "failed", "拿不到 stdout 管道: "+err.Error()
		return
	}
	cmd.Stderr = p.errBuf
	if err := cmd.Start(); err != nil {
		p.state.State, p.state.Err = "failed", "拉起进程失败: "+err.Error()
		return
	}
	p.proc, p.stdin = cmd, stdin
	p.state.PID = cmd.Process.Pid
	p.state.StartedMs = time.Now().UnixMilli()

	// 读线程必须先起来，再发握手 —— 否则握手响应没人接。
	go p.readerLoop(bufio.NewReader(stdout))

	res, err := p.call("tools/list", map[string]interface{}{}, pluginHandshake)
	if err != nil {
		p.state.State = "failed"
		p.state.Err = "握手失败: " + err.Error() + p.tailErr()
		_ = cmd.Process.Kill()
		return
	}
	var module struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(res, &module)
	names := make([]string, 0, len(module.Tools))
	for _, t := range module.Tools {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}
	p.state.State = "loaded"
	p.state.Tools = names
	p.state.ToolCount = len(names)
}

func (p *srvPlugin) tailErr() string {
	if t := p.errBuf.Tail(300); t != "" {
		return "；stderr: " + t
	}
	return ""
}

// readerLoop 是**唯一的** stdout 读者。
// 它要分清两种报文（这就是重构的全部理由）：
func (p *srvPlugin) readerLoop(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			// 进程没了：把所有挂着的调用立刻失败，别让调用方干等到超时
			p.mu.Lock()
			for id, ch := range p.pend {
				ch <- rpcResp{err: fmt.Errorf("插件进程已退出: %v%s", err, p.tailErr())}
				delete(p.pend, id)
			}
			if p.state.State == "loaded" {
				p.state.State = "failed"
				p.state.Err = "进程已退出: " + err.Error() + p.tailErr()
			}
			p.mu.Unlock()
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var probe map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &probe) != nil {
			continue // 插件打的日志之类，跳过
		}
		if _, isReq := probe["method"]; isReq {
			go p.handleReverse(line)
			continue
		}
		var id int64
		if raw, ok := probe["id"]; ok {
			_ = json.Unmarshal(raw, &id)
		}
		p.mu.Lock()
		ch := p.pend[id]
		delete(p.pend, id)
		p.mu.Unlock()
		if ch != nil {
			var e error
			if raw, ok := probe["error"]; ok && len(raw) > 0 && string(raw) != "null" {
				e = fmt.Errorf("插件返回错误: %s", strings.Trim(string(raw), `"`))
			}
			ch <- rpcResp{result: probe["result"], err: e}
		}
	}
}

func (p *srvPlugin) writeLine(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	p.wrMu.Lock()
	defer p.wrMu.Unlock()
	if p.stdin == nil {
		return fmt.Errorf("插件 stdin 不可用")
	}
	_, err = p.stdin.Write(append(b, '\n'))
	return err
}

// call 发一条请求并等响应（带超时）。超时后**必须把 pending 项删掉**，
// 否则响应迟到时会往一个没人收的 chan 里写，读线程就卡住了。
func (p *srvPlugin) call(method string, params interface{}, timeout time.Duration) (json.RawMessage, error) {
	p.mu.Lock()
	if p.state.State != "loaded" && method != "tools/list" {
		st, e := p.state.State, p.state.Err
		p.mu.Unlock()
		return nil, fmt.Errorf("插件未在运行（%s）: %s", st, e)
	}
	p.nextID++
	id := p.nextID
	ch := make(chan rpcResp, 1)
	p.pend[id] = ch
	p.state.Calls++
	p.mu.Unlock()

	if err := p.writeLine(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	}); err != nil {
		p.mu.Lock()
		delete(p.pend, id)
		p.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-ch:
		return r.result, r.err
	case <-time.After(timeout):
		p.mu.Lock()
		delete(p.pend, id)
		p.mu.Unlock()
		return nil, fmt.Errorf("调用超时（%v 内没等到 %s 的响应）", timeout, method)
	}
}

// handleReverse 处理插件的反向请求（host/call）。
//
// 这里是**能力白名单**的执法点：plugin.json 的 host_caps 里没声明的能力一律拒绝。
// 理由：插件一旦能调 deploy_file 就等于能用管理员权限，所以"它能要什么"必须是
// 打开文件就能看见的，不能靠代码里隐式允许。
func (p *srvPlugin) handleReverse(line string) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Cap  string          `json:"cap"`
			Args json.RawMessage `json:"args"`
		} `json:"params"`
	}
	if json.Unmarshal([]byte(line), &req) != nil {
		return
	}
	reply := func(res interface{}, errMsg string) {
		m := map[string]interface{}{"jsonrpc": "2.0"}
		if len(req.ID) > 0 {
			m["id"] = json.RawMessage(req.ID)
		} else {
			m["id"] = nil
		}
		if errMsg != "" {
			m["error"] = errMsg
		} else {
			m["result"] = res
		}
		_ = p.writeLine(m)
	}
	if req.Method != "host/call" {
		p.host.auditLog(p.id, req.Method, false, "未知的反向方法")
		reply(nil, "未知的反向方法: "+req.Method+"（目前只支持 host/call）")
		return
	}
	cap := req.Params.Cap
	if cap == "" {
		reply(nil, "host/call 缺 cap")
		return
	}
	if !p.caps[cap] {
		// 而是这套设计的安全边界：能力可见、可审计、按声明临时授权。
		var decl []string
		for c := range p.caps {
			decl = append(decl, c)
		}
		msg := fmt.Sprintf("未声明的能力 %q（%s 只声明了: %s）", cap, p.id, strings.Join(decl, ","))
		p.host.auditLog(p.id, cap, false, msg)
		reply(nil, msg)
		return
	}
	res, errMsg := p.host.dispatch(p.id, cap, req.Params.Args)
	p.host.auditLog(p.id, cap, errMsg == "", errMsg)
	if errMsg != "" {
		reply(nil, errMsg)
		return
	}
	reply(res, "")
}

// dispatch 是宿主真正"提供"的能力。这一版实现了三个：
//   report      留痕（插件把进展/结果交给宿主，管理端可见）
//   state_read  读宿主持有的键值
//   state_write 写宿主持有的键值
//
// 明确回"尚未实现"—— 而不是假装成功（那会让插件以为文件投出去了）。
func (h *PluginHost) dispatch(plugin, cap string, args json.RawMessage) (interface{}, string) {
	var a map[string]interface{}
	_ = json.Unmarshal(args, &a)
	str := func(k string) string {
		if a == nil {
			return ""
		}
		s, _ := a[k].(string)
		return s
	}
	switch cap {
	case "report":
		msg := str("message")
		if msg == "" {
			msg = str("text")
		}
		log.Printf("[PluginHost][report] %s: %s", plugin, msg)
		return map[string]interface{}{"ok": true, "received": msg}, ""
	case "state_read":
		key := str("key")
		h.kvMu.Lock()
		v, ok := h.kv[key]
		h.kvMu.Unlock()
		if !ok {
			return map[string]interface{}{"key": key, "value": "", "exists": false}, ""
		}
		return map[string]interface{}{"key": key, "value": v, "exists": true}, ""
	case "state_write":
		key, val := str("key"), str("value")
		if key == "" {
			return nil, "state_write 缺 key"
		}
		h.kvMu.Lock()
		h.kv[key] = val
		h.kvMu.Unlock()
		return map[string]interface{}{"ok": true, "key": key}, ""
	case "deploy_file", "upload_file", "rollback", "invoke_tool", "routes", "agents", "exec":
		return nil, "能力 " + cap + " 尚未实现（本版只通了 report / state_read / state_write）"
	}
	return nil, "宿主不认识的能力: " + cap
}

func (h *PluginHost) StateFor(id string) PluginRunState {
	h.mu.Lock()
	p := h.plugins[id]
	h.mu.Unlock()
	if p == nil {
		return PluginRunState{ID: id, State: "failed", Err: "宿主里没有这个插件"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (h *PluginHost) States() map[string]PluginRunState {
	out := map[string]PluginRunState{}
	h.mu.Lock()
	ids := append([]string{}, h.order...)
	h.mu.Unlock()
	for _, id := range ids {
		out[id] = h.StateFor(id)
	}
	return out
}

// CallTool 给 HTTP 层用：调某个 server 侧插件的工具。
func (h *PluginHost) CallTool(plugin, tool string, args map[string]interface{}) (json.RawMessage, error) {
	h.mu.Lock()
	p := h.plugins[plugin]
	h.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("没有这个 server 侧插件: %s", plugin)
	}
	if args == nil {
		args = map[string]interface{}{}
	}
	return p.call("tools/call", map[string]interface{}{"name": tool, "arguments": args}, pluginCallTimeout)
}

func (h *PluginHost) KV() map[string]string {
	h.kvMu.Lock()
	defer h.kvMu.Unlock()
	out := map[string]string{}
	for k, v := range h.kv {
		out[k] = v
	}
	return out
}

// registerPluginRoutes 挂上 server 侧插件的两个入口。
//
// 与 agent 侧插件的分界很关键：agent 侧工具走 /api/mcp 中继到受管端，
// 而这里的是**跑在服务端进程里的插件**，直接本机调用，不经受管端、也不该经。
func registerPluginRoutes(mux *http.ServeMux, sessions *SessionManager, host *PluginHost) {
	mux.HandleFunc("/api/plugin/call", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			Plugin    string                 `json:"plugin"`
			Tool      string                 `json:"tool"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if body.Plugin == "" || body.Tool == "" {
			writeJSON(w, 400, map[string]string{"error": "缺少 plugin 或 tool"})
			return
		}
		res, err := host.CallTool(body.Plugin, body.Tool, body.Arguments)
		if err != nil {
			// 失败原因原样透出（"插件未在运行"/"调用超时"…），不要吞成一句"失败"
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "result": json.RawMessage(res)})
	})

	mux.HandleFunc("/api/plugins/audit", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "audit": host.Audit(), "state": host.KV(),
			"note": "audit = 每次 host/call 的留痕（含被拒绝的）；state = 插件通过 state_write 写的键值",
		})
	})
}

// RegisterRoutes 把插件声明的路径注册到内核的 mux 上，收到请求就**转发给插件**。
//
// 为什么用"工具调用"这条通道转发：宿主与插件之间只有 stdio 这一条链路。
// 所以约定插件实现一个名为 http/request 的工具，宿主把
// {method, path, query, body} 交给它，它回 {status, body}。
// 好处是协议只有一套（不用为 HTTP 再造一种报文），代价是 http/request
// 会出现在 plugins 的工具列表里（可被有会话的人调用，由插件自己校验参数）。
//
// 必须在 Start() **之后**调用：路由是从 plugin.json 读出来的，Start 才读。
// artifactAuth 由 main 集成（宿主本身不持有工件台账）。
// 为什么要单独一种鉴权：外置工具（R6MLock）用的是**投放链签发的工件密钥**，
// 与 per-agent 密钥是两套凭据、两个签发者。混用等于把两套信任模型揉在一起。
func (h *PluginHost) RegisterRoutes(mux *http.ServeMux, sessions *SessionManager,
	agents *AgentRegistry, artifactAuth func(key, hwid string) bool) {
	h.mu.Lock()
	ids := append([]string{}, h.order...)
	h.mu.Unlock()
	n := 0
	for _, id := range ids {
		h.mu.Lock()
		p := h.plugins[id]
		h.mu.Unlock()
		if p == nil {
			continue
		}
		for _, rt := range p.routes {
			route, pluginID := rt, id
			mux.HandleFunc(route.Path, func(w http.ResponseWriter, r *http.Request) {
				// 方法不符：明确 405，而不是把 GET 当 POST 转给插件
				if route.Method != "" && !strings.EqualFold(r.Method, route.Method) {
					writeJSON(w, 405, map[string]string{
						"error": "该方法未声明: " + r.Method + "（该路径只声明了 " + route.Method + "）"})
					return
				}
				// ── 鉴权：按插件声明的方式 ──
				switch route.Auth {
				case "agent":
					hw := r.Header.Get(hdrAgentHWID)
					if hw == "" {
						hw = r.URL.Query().Get("hwid")
					}
					if !checkAgentAuth(r, hw, agents) {
						writeJSON(w, 401, map[string]string{"error": "unauthorized（该路由声明为 agent 鉴权）"})
						return
					}
				case "session":
					if !checkAuth(r, sessions) {
						writeJSON(w, 401, map[string]string{"error": "unauthorized（该路由声明为会话鉴权）"})
						return
					}
				case "artifact":
					// R6MLock 这类外置工具发的是 X-Artifact-Key（外加 X-Agent-HWID）——
					// 它是投放链签发的那把钥匙，**不需要**改工具代码就能接上插件路由。
					if artifactAuth == nil ||
						!artifactAuth(r.Header.Get(hdrArtifactKey), r.Header.Get(hdrAgentHWID)) {
						writeJSON(w, 401, map[string]string{
							"error": "unauthorized（该路由声明为 artifact 鉴权：需 X-Artifact-Key + X-Agent-HWID）"})
						return
					}
				case "none":
					// 显式声明不需要鉴权才临时授权
				default:
					// 没声明 = 拒绝。默认临时授权是最容易出的事故：
					// 一个忘了写 auth 的路由会变成任何人可打的维护通道。
					writeJSON(w, 500, map[string]string{
						"error": "插件没为 " + route.Path + " 声明 auth（agent|session|none），拒绝转发以免裸奔"})
					return
				}
				body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				res, err := h.CallTool(pluginID, "http/request", map[string]interface{}{
					"method": r.Method, "path": r.URL.Path,
					"query": r.URL.RawQuery, "body": string(body),
				})
				if err != nil {
					writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
					return
				}
				// 插件回 {status, body}；body 是字符串就原样透出（插件自己决定是不是 JSON）
				var out struct {
					Status int             `json:"status"`
					Body   json.RawMessage `json:"body"`
				}
				if json.Unmarshal(res, &out) != nil || out.Status == 0 {
					// 插件没按约定回：把原始结果给它，并说明约定
					writeJSON(w, 200, map[string]interface{}{
						"ok": false, "raw": json.RawMessage(res),
						"error": "插件对 http/request 的回复不符合 {status, body} 约定"})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(out.Status)
				_, _ = w.Write(out.Body)
			})
			n++
		}
	}
	if n > 0 {
		log.Printf("[PluginHost] 已注册 %d 条插件路由（由插件在 plugin.json 里声明）", n)
	}
}
