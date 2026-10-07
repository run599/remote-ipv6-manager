package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════
// C2 Server - Go rewrite
// Features: Agent management, MCP relay, Quiz, Session
// ═══════════════════════════════════════════════

// Agent represents a connected client
type Agent struct {
	HWID      string `json:"hwid"`
	User      string `json:"user"`
	OS        string `json:"os"`
	IP        string `json:"ip"`
	Online    bool   `json:"online"`
	LastSeen  int64  `json:"last_seen"`
	Integrity string `json:"integrity,omitempty"` // "ok" / "tampered:..." / ""(未上报)
	// per-agent 密钥不序列化（agent.key 字段不进 JSON）
}

// AgentRegistry manages all connected agents
type AgentRegistry struct {
	mu             sync.Mutex
	agents         map[string]*Agent
	keys           map[string]string // hwid -> per-agent key（不出现在 /api/agents 输出）
	clearIntegrity map[string]bool   // hwid -> 待下发的"解除熔断"指令（人工确认通道）
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents:         make(map[string]*Agent),
		keys:           make(map[string]string),
		clearIntegrity: make(map[string]bool),
	}
}

// IssueKey 为 agent 生成并记住独立密钥。
// 已有密钥则复用（幂等），保证客户端重启后仍能认证。
func (r *AgentRegistry) IssueKey(hwid string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[hwid]; ok {
		return k
	}
	b := make([]byte, 32)
	rand.Read(b)
	k := hex.EncodeToString(b)
	r.keys[hwid] = k
	return k
}

// RequestIntegrityClear 运维确认排查完毕后请求解除该 agent 的熔断
func (r *AgentRegistry) RequestIntegrityClear(hwid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[hwid]; !ok {
		return false
	}
	r.clearIntegrity[hwid] = true
	return true
}

// ConsumeIntegrityClear 取走一次解除指令（只下发一次）
func (r *AgentRegistry) ConsumeIntegrityClear(hwid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clearIntegrity[hwid] {
		delete(r.clearIntegrity, hwid)
		return true
	}
	return false
}

// HasKey 该 hwid 是否已完成首次登记（per-agent 密钥已存在）
func (r *AgentRegistry) HasKey(hwid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.keys[hwid]
	return ok
}

// AgentKey 返回该 agent 的独立密钥；不存在返回空串
func (r *AgentRegistry) AgentKey(hwid string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys[hwid]
}

// RevokeKey 吊销（内存态）；客户端需重新用引导密钥注册
func (r *AgentRegistry) RevokeKey(hwid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, hwid)
}

func (r *AgentRegistry) Register(hwid, user, os, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[hwid]
	if !ok {
		a = &Agent{HWID: hwid}
		r.agents[hwid] = a
	}
	a.User = user
	a.OS = os
	a.IP = ip
	a.Online = true
	a.LastSeen = time.Now().UnixMilli()
	log.Printf("[Agent] Registered: %s user=%s", hwid[:min(12, len(hwid))], user)
}

func (r *AgentRegistry) Heartbeat(hwid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[hwid]; ok {
		a.Online = true
		a.LastSeen = time.Now().UnixMilli()
	}
}

// SetIntegrity 记录 agent 上报的完整性状态
func (r *AgentRegistry) SetIntegrity(hwid, integrity string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[hwid]; ok {
		a.Integrity = integrity
	}
	// 心跳可能先于 register（首次注册时），未知 hwid 静默忽略
}

func (r *AgentRegistry) GetAll() []Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var list []Agent
	for _, a := range r.agents {
		list = append(list, *a)
	}
	return list
}

func (r *AgentRegistry) OnlineCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, a := range r.agents {
		if a.Online {
			n++
		}
	}
	return n
}

func (r *AgentRegistry) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UnixMilli()
	for _, a := range r.agents {
		if a.Online && (now-a.LastSeen) > 60000 {
			a.Online = false
		}
	}
}

// SessionManager handles login/auth
type SessionManager struct {
	mu       sync.Mutex
	user     string
	pass     string
	sessions map[string]int64 // token -> 过期时间 (unix ms)
}

const sessionTTL = 24 * time.Hour

func NewSessionManager(user, pass string) *SessionManager {
	return &SessionManager{user: user, pass: pass, sessions: make(map[string]int64)}
}

func (s *SessionManager) Login(user, pass string) string {
	// 常数时间比较，防止时序侧信道
	u := subtle.ConstantTimeCompare([]byte(user), []byte(s.user))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(s.pass))
	if u != 1 || p != 1 {
		return ""
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := "sess-" + hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(sessionTTL).UnixMilli()
	s.mu.Unlock()
	log.Printf("[Session] Login: %s", user)
	return token
}

func (s *SessionManager) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().UnixMilli() > exp {
		delete(s.sessions, token)
		return false
	}
	return true
}

// Cleanup 移除过期会话
func (s *SessionManager) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	for t, exp := range s.sessions {
		if now > exp {
			delete(s.sessions, t)
		}
	}
}

// LoginLimiter 登录限速：同一 IP 连续失败 5 次后锁定 1 分钟
type LoginLimiter struct {
	mu      sync.Mutex
	fails   map[string]int
	blocked map[string]int64 // ip -> 解封时间 (unix ms)
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{fails: make(map[string]int), blocked: make(map[string]int64)}
}

func (l *LoginLimiter) Allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blocked[ip]
	if !ok {
		return true
	}
	if time.Now().UnixMilli() > until {
		delete(l.blocked, ip)
		// 注意：不清零 l.fails —— 失败计数必须跨锁定期累积，
		// 否则攻击者可以每 5 次失败/分钟无限尝试
		return true
	}
	return false
}

func (l *LoginLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip]++
	if l.fails[ip] >= 5 {
		// 指数退避：第 5 次锁 1 分钟，此后每次失败翻倍，上限约 64 分钟
		extra := l.fails[ip] - 5
		if extra > 6 {
			extra = 6
		}
		lockFor := time.Minute << uint(extra)
		l.blocked[ip] = time.Now().Add(lockFor).UnixMilli()
		log.Printf("[Session] IP %s 登录失败 %d 次，锁定 %s", ip, l.fails[ip], lockFor)
	}
}

func (l *LoginLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
	delete(l.blocked, ip)
}

// Cleanup 清理已解封且失败计数已归零的条目，防止 map 无界增长
func (l *LoginLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UnixMilli()
	for ip, until := range l.blocked {
		if now > until && l.fails[ip] == 0 {
			delete(l.blocked, ip)
			delete(l.fails, ip)
		}
	}
}

// CommandQueue for agent commands
type CommandQueue struct {
	mu      sync.Mutex
	cmds    map[string][]Command   // hwid -> [Command]
	results map[string]resultEntry // requestId -> result (async, 带 TTL 防内存积压)
	owner   map[string]ownerEntry  // requestId -> 归属 hwid（阻止 agent 伪造他机结果）
}

type resultEntry struct {
	value    string
	deadline int64 // unix ms
}

// ownerEntry 记录某个 requestId 归属于哪个 agent，以及归属信息的清理时限
type ownerEntry struct {
	hwid     string
	deadline int64 // unix ms
}

const (
	resultTTL        = 30 * time.Minute
	commandTTL       = 10 * time.Minute
	maxQueuePerAgent = 64
	maxQueueTotal    = 8192
)

type Command struct {
	RequestID string
	HWID      string
	Method    string
	Params    string
	Enqueued  int64 // unix ms，超时未取走即丢弃（避免上线后执行陈旧指令）
}

func NewCommandQueue() *CommandQueue {
	return &CommandQueue{
		cmds:    make(map[string][]Command),
		results: make(map[string]resultEntry),
		owner:   make(map[string]ownerEntry),
	}
}

func (q *CommandQueue) Enqueue(hwid, method, params string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.cmds[hwid]) >= maxQueuePerAgent {
		return "", fmt.Errorf("per-agent queue full (max %d)", maxQueuePerAgent)
	}
	total := 0
	for _, v := range q.cmds {
		total += len(v)
	}
	if total >= maxQueueTotal {
		return "", fmt.Errorf("global queue full (max %d)", maxQueueTotal)
	}
	reqID := "req-" + randomHex(16) // 不可预测，避免被猜出他人 request_id
	now := time.Now()
	q.cmds[hwid] = append(q.cmds[hwid], Command{
		RequestID: reqID, HWID: hwid, Method: method, Params: params, Enqueued: now.UnixMilli(),
	})
	q.owner[reqID] = ownerEntry{hwid: hwid, deadline: now.Add(resultTTL + commandTTL).UnixMilli()}
	return reqID, nil
}

func (q *CommandQueue) Dequeue(hwid string) (Command, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cmds, ok := q.cmds[hwid]
	if !ok || len(cmds) == 0 {
		delete(q.cmds, hwid) // 不留空切片，避免 map 无界增长
		return Command{}, false
	}
	now := time.Now().UnixMilli()
	// 丢弃已过期指令：agent 离线很久后重新上线时不应执行陈旧命令
	for len(cmds) > 0 && now-cmds[0].Enqueued > commandTTL.Milliseconds() {
		cmd := cmds[0]
		delete(q.owner, cmd.RequestID)
		log.Printf("[Server] 丢弃过期指令 reqID=%s hwid=%s（入队 %d ms 前）", cmd.RequestID, hwid, now-cmd.Enqueued)
		cmds = cmds[1:]
	}
	if len(cmds) == 0 {
		delete(q.cmds, hwid)
		return Command{}, false
	}
	cmd := cmds[0]
	if len(cmds) == 1 {
		delete(q.cmds, hwid)
	} else {
		q.cmds[hwid] = cmds[1:]
	}
	return cmd, true
}

// StoreResult 落库结果；hwid 必须与该 requestId 的归属一致，
// 否则拒绝（防止某个已失陷 agent 用猜到的 request_id 污染他机结果）
func (q *CommandQueue) StoreResult(reqID, hwid, result string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if o, ok := q.owner[reqID]; ok && o.hwid != hwid {
		return fmt.Errorf("request_id %s 不属于该 agent", reqID)
	}
	q.results[reqID] = resultEntry{value: result, deadline: time.Now().Add(resultTTL).UnixMilli()}
	delete(q.owner, reqID)
	return nil
}

// GetResult retrieves and deletes a stored result
func (q *CommandQueue) GetResult(reqID string) (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.results[reqID]
	if ok {
		delete(q.results, reqID)
		if time.Now().UnixMilli() > e.deadline {
			return "", false
		}
	}
	return e.value, ok
}

// Cleanup 清理过期 result，防止伪造请求打爆内存
func (q *CommandQueue) Cleanup() {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().UnixMilli()
	for id, e := range q.results {
		if now > e.deadline {
			delete(q.results, id)
		}
	}
	for id, o := range q.owner {
		if now > o.deadline {
			delete(q.owner, id)
		}
	}
	for hwid, cmds := range q.cmds {
		if len(cmds) == 0 {
			delete(q.cmds, hwid)
		}
	}
}

// randomHex 生成 n 字节的随机 hex 串
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 熵源不可用是致命情况，绝不退回可预测值
		log.Fatalf("[Server] 随机数生成失败: %v", err)
	}
	return hex.EncodeToString(b)
}

func main() {
	// 环境变量兜底
	port := getEnvInt("C2_PORT", 8080)
	user := getEnv("C2_USER", "admin")
	pass := getEnv("C2_PASS", "changeme")

	// 子命令派发
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			runServer(port, user, pass, os.Args[2:])
			return
		case "agent":
			runAgentCmd(os.Args[2:])
			return
		case "mcp":
			runMcpCmd(os.Args[2:])
			return
		case "version":
			fmt.Println("C2 Server v1.0.0")
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}
	// 无参数默认 serve（兼容旧脚本）
	runServer(port, user, pass, nil)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func printUsage() {
	fmt.Println(`C2 Server - 命令行用法:
  c2-server serve [--port N] [--user U] [--pass P]  启动服务端
  c2-server agent list                                              列出在线 Agent
  c2-server agent info <hwid>                                       查看 Agent 详情
  c2-server mcp call <hwid> <tool> <json-args>                      调用 MCP 工具（同步等待结果）
  c2-server version                                                 显示版本
  c2-server help                                                    显示帮助

环境变量兜底: C2_PORT C2_USER C2_PASS C2_AGENT_KEY
示例:
  c2-server serve --port 8080
  c2-server agent list
  c2-server mcp call BCA92F84 execute '{"command":"whoami"}'`)
}

func runServer(port int, user, pass string, extraArgs []string) {
	// 解析 serve 子命令的额外参数
	for i := 0; i < len(extraArgs); i++ {
		switch extraArgs[i] {
		case "--port":
			if i+1 < len(extraArgs) {
				port, _ = strconv.Atoi(extraArgs[i+1])
				i++
			}
		case "--user":
			if i+1 < len(extraArgs) {
				user = extraArgs[i+1]
				i++
			}
		case "--pass":
			if i+1 < len(extraArgs) {
				pass = extraArgs[i+1]
				i++
			}
		}
	}

	agents := NewAgentRegistry()
	sessions := NewSessionManager(user, pass)
	cmds := NewCommandQueue()
	limiter := NewLoginLimiter()

	// agent 共享密钥：所有 agent 接口必须携带 X-Agent-Key 头
	agentKey := loadOrCreateAgentKey()
	log.Printf("[AgentKey] 共享密钥已加载（客户端通过环境变量 R6M_AGENT_KEY 或 --agent-key 传入）")

	// 默认口令告警
	if user == "admin" && pass == "changeme" {
		log.Printf("[安全警告] 当前使用默认口令 admin/changeme！请通过 --pass 或 C2_PASS 立即修改")
	}

	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			agents.Cleanup()
			sessions.Cleanup()
			cmds.Cleanup()
			limiter.Cleanup()
		}
	}()

	mux := http.NewServeMux()

	// Login
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "POST required"})
			return
		}
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr) // 去掉端口，按 IP 限速
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !limiter.Allowed(clientIP) {
			writeJSON(w, 429, map[string]string{"error": "too many failures, retry later"})
			return
		}
		limitJSONBody(w, r)
		var body struct{ User, Pass string }
		json.NewDecoder(r.Body).Decode(&body)
		token := sessions.Login(body.User, body.Pass)
		if token == "" {
			limiter.RecordFailure(clientIP)
			writeJSON(w, 401, map[string]string{"error": "bad credentials"})
			return
		}
		limiter.RecordSuccess(clientIP)
		http.SetCookie(w, &http.Cookie{Name: "c2session", Value: token, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Health —— 不需要任何凭据的最小探针。
	// 客户端在发送任何密钥之前先打这个接口完成 TLS 指纹校验，
	// 这样指纹不匹配时凭据根本不会离开本机。
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"ok": true, "service": "r6m-server", "version": "1.0.0"})
	})

	// Integrity clear —— 运维确认排查完毕后解除该 agent 的熔断
	mux.HandleFunc("/api/integrity/clear", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		if !agents.RequestIntegrityClear(hwid) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		log.Printf("[Server] 运维请求解除熔断: %s（将在其下次心跳的下一次 poll 下发）", hwid)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Agent rekey —— 运维吊销某 hwid 的 per-agent 密钥，允许其用引导密钥重新登记。
	// 这是 409 "already enrolled" 的官方出路：客户端换机/重装后才需要。
	mux.HandleFunc("/api/agent/rekey", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		if !agents.HasKey(hwid) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		agents.RevokeKey(hwid)
		log.Printf("[Server] 运维吊销 %s 的 per-agent 密钥，允许其用引导密钥重新登记", hwid)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Status
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]int{"agents_online": agents.OnlineCount(), "agents_total": len(agents.GetAll())})
	})

	// Agents
	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, agents.GetAll())
	})

	// Agent register — 引导密钥认证；成功后下发本机独立密钥
	mux.HandleFunc("/api/agent/register", func(w http.ResponseWriter, r *http.Request) {
		limitJSONBody(w, r)
		bodyBytes, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		json.Unmarshal(bodyBytes, &body)
		hwid, _ := body["hwid"].(string)
		user, _ := body["user"].(string)
		osName, _ := body["os"].(string)
		// Handle nested info object from Client Stub
		if user == "" {
			if info, ok := body["info"].(map[string]interface{}); ok {
				user, _ = info["user"].(string)
				osName, _ = info["os"].(string)
			}
		}
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		// 两条凭据通道，缺一不可：
		//  ① 引导密钥 —— 仅用于首次登记一个全新 hwid
		//  ② 该 hwid 自己的 per-agent 密钥 —— 用于幂等复核（客户端重启后重新注册）
		// 绝不允许"持有引导密钥就给已登记 hwid 补发密钥"，否则任一失陷客户端
		// 都能冒名接管其他节点（引导密钥分发在每台客户端的 r6m.ini 里）。
		presented := r.Header.Get("X-Agent-Key")
		bootstrapOK := checkBootstrapAuth(r, agentKey)
		perAgentOK := false
		if !bootstrapOK && presented != "" && agents.HasKey(hwid) {
			perAgentOK = subtle.ConstantTimeCompare([]byte(presented), []byte(agents.AgentKey(hwid))) == 1
		}
		if !bootstrapOK && !perAgentOK {
			log.Printf("[Server] 注册鉴权失败: hwid=%s ip=%s", hwid, r.RemoteAddr)
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		log.Printf("[Server] Register: hwid=%s user=%s os=%s ip=%s", hwid, user, osName, r.RemoteAddr)
		// per-agent 密钥：每台机器独立，单机泄露不波及其他 agent。
		// 关键约束：hwid 已登记时，只允许"持有该 hwid 既有密钥"的调用方复核，
		// 绝不用引导密钥把别人的密钥再发一次（否则任何一个持有引导密钥的
		// 客户端都能冒名接管其他节点）。
		if existing := agents.AgentKey(hwid); existing != "" {
			if !perAgentOK {
				log.Printf("[Server] 拒绝冒名注册: hwid=%s 已登记，调用方只提供了引导密钥（ip=%s）", hwid, r.RemoteAddr)
				writeJSON(w, 409, map[string]string{"error": "hwid already enrolled, present its per-agent key or ask operator to re-enroll"})
				return
			}
			agents.Register(hwid, user, osName, r.RemoteAddr)
			writeJSON(w, 200, map[string]string{"ok": "true", "agent_key": existing})
			return
		}
		agents.Register(hwid, user, osName, r.RemoteAddr)
		agentKeyForThis := agents.IssueKey(hwid)
		writeJSON(w, 200, map[string]string{"ok": "true", "agent_key": agentKeyForThis})
	})

	// Heartbeat — per-agent 密钥
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		limitJSONBody(w, r)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		hwid, _ := body["hwid"].(string)
		if !checkAgentAuth(r, hwid, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if hwid != "" {
			agents.Heartbeat(hwid)
			// 完整性上报（AntiHook 三段式之二）
			if integrity, ok := body["integrity"].(string); ok && integrity != "" {
				agents.SetIntegrity(hwid, integrity)
				if integrity != "ok" {
					// 醒目告警：运维无需盯日志，agent 列表即见标红状态
					log.Printf("[!!完整性告警!!] agent=%s 状态=%s —— 该端点疑似被注入，建议停止对其下发指令并排查", hwid, integrity)
				}
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Agent poll — per-agent 密钥
	mux.HandleFunc("/api/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		limitJSONBody(w, r)
		bodyBytes, _ := io.ReadAll(r.Body)

		var body map[string]interface{}
		json.Unmarshal(bodyBytes, &body)
		hwid, _ := body["hwid"].(string)
		if !checkAgentAuth(r, hwid, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		log.Printf("[Server] Poll parsed HWID: '%s'", hwid)
		agents.Heartbeat(hwid)
		resp := map[string]interface{}{}
		if agents.ConsumeIntegrityClear(hwid) {
			// 运维已确认排查完毕：下发一次解除熔断（AntiHook 三段式的复位通道）
			resp["clear_integrity"] = true
			log.Printf("[Server] 已向 %s 下发解除熔断指令", hwid)
		}
		if cmd, ok := cmds.Dequeue(hwid); ok {
			log.Printf("[Server] Dequeue command for %s: reqID=%s method=%s", hwid, cmd.RequestID, cmd.Method)
			resp["request_id"] = cmd.RequestID
			resp["method"] = cmd.Method
			if json.Valid([]byte(cmd.Params)) {
				resp["params"] = json.RawMessage(cmd.Params)
			} else {
				// 下游会把它当 JSON 解析；非法时明确降级为 {} 而不是吐出坏字节
				log.Printf("[Server] 指令 params 非法 JSON，降级为空对象: reqID=%s", cmd.RequestID)
				resp["params"] = json.RawMessage("{}")
			}
		} else {
			log.Printf("[Server] No command for %s", hwid)
		}
		writeJSON(w, 200, resp)
	})

	// Agent result — per-agent 密钥（按请求头 X-Agent-HWID 认证）
	mux.HandleFunc("/api/agent/result", func(w http.ResponseWriter, r *http.Request) {
		// result 的 body 里只有 request_id 没有 hwid，hwid 从头里取
		reqHWID := r.Header.Get("X-Agent-HWID")
		if !checkAgentAuth(r, reqHWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitJSONBody(w, r)
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Printf("[Server] Result decode error: %v", err)
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		reqID, _ := body["request_id"].(string)
		// Result can be string or object — marshal to string for storage
		resultBytes, _ := json.Marshal(body["result"])
		resultStr := string(resultBytes)
		log.Printf("[Server] Result received: reqID=%s hwid=%s len=%d", reqID, reqHWID, len(resultStr))
		if err := cmds.StoreResult(reqID, reqHWID, resultStr); err != nil {
			log.Printf("[Server] 拒绝结果落库: %v", err)
			writeJSON(w, 403, map[string]string{"error": "request_id not owned by this agent"})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// MCP tool call (async: enqueue + return request_id)
	mux.HandleFunc("/api/mcp", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e := recover(); e != nil {
				log.Printf("[Server] MCP panic: %v", e)
				writeJSON(w, 500, map[string]interface{}{"ok": false, "error": "internal error"})
			}
		}()
		if !checkAuth(r, sessions) {
			log.Printf("[Server] MCP auth failed")
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			AgentHWID string          `json:"agent_hwid"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Printf("[Server] MCP decode error: %v", err)
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		log.Printf("[Server] MCP request: hwid=%s name=%s args=%s", body.AgentHWID, body.Name, string(body.Arguments))
		if body.AgentHWID == "" || body.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid or name"})
			return
		}
		if !agents.HasKey(body.AgentHWID) {
			// 未登记过的 hwid 不允许入队，否则队列会被无界撑大
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		rpcParams, _ := json.Marshal(map[string]interface{}{"name": body.Name, "arguments": body.Arguments})
		reqID, err := cmds.Enqueue(body.AgentHWID, "tools/call", string(rpcParams))
		if err != nil {
			log.Printf("[Server] 入队失败: %v", err)
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[Server] MCP enqueue for %s: reqID=%s name=%s", body.AgentHWID, reqID, body.Name)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "request_id": reqID})
	})

	// MCP poll result (CLI polls this after sending /api/mcp)
	mux.HandleFunc("/api/mcp/result", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		reqID := r.URL.Query().Get("request_id")
		if reqID == "" {
			writeJSON(w, 400, map[string]string{"error": "missing request_id"})
			return
		}
		result, ok := cmds.GetResult(reqID)
		if ok {
			writeJSON(w, 200, map[string]interface{}{"ok": true, "result": json.RawMessage(result)})
		} else {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "status": "pending"})
		}
	})

	// ═══ File Store path ═══
	// 优先用环境变量，否则用可执行文件同级目录下的 filestore/
	filestoreDir := func() string {
		if v := os.Getenv("C2_FILESTORE"); v != "" {
			return v
		}
		exePath, _ := os.Executable()
		return filepath.Join(filepath.Dir(exePath), "filestore")
	}()

	// ═══ Runtime Sync ═══
	// Agent pulls embedded runtime (Python/Node) — agent auth required
	mux.HandleFunc("/api/runtime", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get("X-Agent-HWID"), agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		// 列出可用运行时
		var runtimes []map[string]interface{}
		entries, _ := os.ReadDir(filestoreDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// 只暴露 python/node 嵌入式包
			if isRuntimeZip(name) {
				info, _ := e.Info()
				runtimes = append(runtimes, map[string]interface{}{
					"name": name, "size": info.Size(),
				})
			}
		}
		writeJSON(w, 200, runtimes)
	})
	mux.HandleFunc("/api/runtime/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get("X-Agent-HWID"), agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		name := r.URL.Query().Get("name")
		path, err := safeJoin(filestoreDir, name)
		if err != nil {
			log.Printf("[Server] Path rejected (runtime/get): %s -> %v", name, err)
			writeJSON(w, 400, map[string]string{"error": "invalid name"})
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name))
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// ═══ Plugin Sync ═══
	// Agent pulls plugin list from server (agent auth required)
	mux.HandleFunc("/api/plugins", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get("X-Agent-HWID"), agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		pluginDir := filepath.Join(filestoreDir, "plugins")
		entries, err := os.ReadDir(pluginDir)
		if err != nil {
			// 也检查根 filestore 下有没有直接的 plugin 目录
			pluginDir = filestoreDir
			entries, err = os.ReadDir(pluginDir)
			if err != nil {
				writeJSON(w, 200, []interface{}{})
				return
			}
		}
		var plugins []map[string]interface{}
		for _, e := range entries {
			if !e.IsDir() {
				// 非目录文件，跳过
				continue
			}
			// 检查目录下有没有 plugin.json
			pjson := filepath.Join(pluginDir, e.Name(), "plugin.json")
			if _, err := os.Stat(pjson); err != nil {
				continue
			}
			// 读取 plugin.json 获取 name/version
			data, err := os.ReadFile(pjson)
			if err != nil {
				continue
			}
			var meta struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				Command     string `json:"command"`
				Description string `json:"description"`
			}
			json.Unmarshal(data, &meta)
			plugins = append(plugins, map[string]interface{}{
				"id":          e.Name(),
				"name":        meta.Name,
				"version":     meta.Version,
				"command":     meta.Command,
				"description": meta.Description,
			})
		}
		writeJSON(w, 200, plugins)
	})

	// Agent pulls a file from plugin directory (agent auth required)
	mux.HandleFunc("/api/plugins/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get("X-Agent-HWID"), agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		name := r.URL.Query().Get("name") // e.g. "shell_exec/plugin.json"
		// 先在 filestore/plugins/ 下找，再回退到 filestore/ 根目录，两处都做路径校验
		path, err := safeJoin(filepath.Join(filestoreDir, "plugins"), name)
		if err != nil || func() bool { _, e := os.Stat(path); return e != nil }() {
			altPath, altErr := safeJoin(filestoreDir, name)
			if altErr != nil {
				log.Printf("[Server] Path rejected (plugins/get): %s -> %v", name, err)
				writeJSON(w, 400, map[string]string{"error": "invalid name"})
				return
			}
			path = altPath
		}
		info, err := os.Stat(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found: " + name})
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name))
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// ═══ File Store ═══

	// List files
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		entries, err := os.ReadDir(filestoreDir)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "read dir failed"})
			return
		}
		var files []map[string]interface{}
		for _, e := range entries {
			info, _ := e.Info()
			files = append(files, map[string]interface{}{
				"name": e.Name(), "size": info.Size(), "mod_time": info.ModTime().Unix(),
			})
		}
		writeJSON(w, 200, files)
	})

	// List directory contents (panel file explorer) — ?path=<relative-dir>
	mux.HandleFunc("/api/files/list", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		sub := r.URL.Query().Get("path")
		dir := filestoreDir
		if sub != "" {
			p, err := safeJoin(filestoreDir, sub)
			if err != nil {
				log.Printf("[Server] Path rejected (files/list): %s -> %v", sub, err)
				writeJSON(w, 400, map[string]string{"error": "invalid path"})
				return
			}
			dir = p
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		var files []map[string]interface{}
		for _, e := range entries {
			info, _ := e.Info()
			files = append(files, map[string]interface{}{
				"name": e.Name(), "is_dir": e.IsDir(), "size": info.Size(),
				"mod_time": info.ModTime().Unix(),
			})
		}
		writeJSON(w, 200, files)
	})

	// Delete file (panel file explorer) — ?name=<relative-path>
	mux.HandleFunc("/api/files/delete", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != "POST" && r.Method != "DELETE" {
			writeJSON(w, 405, map[string]string{"error": "POST/DELETE required"})
			return
		}
		name := r.URL.Query().Get("name")
		path, err := safeJoin(filestoreDir, name)
		if err != nil {
			log.Printf("[Server] Path rejected (files/delete): %s -> %v", name, err)
			writeJSON(w, 400, map[string]string{"error": "invalid name"})
			return
		}
		// 保护服务端自身的关键文件（相对 filestore 不适用，但防御性拒绝敏感名）
		base := filepath.Base(path)
		if base == "server.crt" || base == "server.key" || base == "agent.key" {
			writeJSON(w, 403, map[string]string{"error": "refusing to delete critical file"})
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		if info.IsDir() {
			writeJSON(w, 400, map[string]string{"error": "directory delete not supported"})
			return
		}
		if err := os.Remove(path); err != nil {
			log.Printf("[Server] Delete failed: %v", err)
			writeJSON(w, 500, map[string]string{"error": "delete failed"})
			return
		}
		log.Printf("[Server] File deleted: %s", name)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Download file (panel/CLI pulls this)
	mux.HandleFunc("/api/files/download", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		name := r.URL.Query().Get("name")
		path, err := safeJoin(filestoreDir, name)
		if err != nil {
			log.Printf("[Server] Path rejected (files/download): %s -> %v", name, err)
			writeJSON(w, 400, map[string]string{"error": "invalid name"})
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name))
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// Upload file (panel pushes this)
	mux.HandleFunc("/api/files/upload", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20) // 64 MB 上限
		file, handler, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "no file"})
			return
		}
		defer file.Close()
		// 文件名只取 basename 并做路径校验，阻止 "..\..\evil.exe" 写入任意位置
		safeName := filepath.Base(filepath.FromSlash(strings.ReplaceAll(handler.Filename, "\\", "/")))
		dstPath, err := safeJoin(filestoreDir, safeName)
		if err != nil {
			log.Printf("[Server] Upload path rejected: %q -> %v", handler.Filename, err)
			writeJSON(w, 400, map[string]string{"error": "invalid filename"})
			return
		}
		dst, err := os.Create(dstPath)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "create failed"})
			return
		}
		defer dst.Close()
		written, err := io.Copy(dst, file)
		if err != nil {
			log.Printf("[Server] 上传写入失败: %s -> %v", safeName, err)
			writeJSON(w, 500, map[string]string{"error": "write failed"})
			return
		}
		log.Printf("[Server] File uploaded: %s (%d bytes, 声明 %d)", safeName, written, handler.Size)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": safeName, "size": handler.Size})
	})

	// Deploy file to agent (enqueue download command)
	mux.HandleFunc("/api/files/deploy", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			AgentHWID string `json:"agent_hwid"`
			FileName  string `json:"file_name"`
			TargetDir string `json:"target_dir"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if !agents.HasKey(body.AgentHWID) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		cmdData, _ := json.Marshal(body)
		if _, err := cmds.Enqueue(body.AgentHWID, "deploy_file", string(cmdData)); err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "status": "dispatched"})
	})

	// Download file (agent pulls this — agent auth required)
	mux.HandleFunc("/api/files/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get("X-Agent-HWID"), agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		name := r.URL.Query().Get("name")
		path, err := safeJoin(filestoreDir, name)
		if err != nil {
			log.Printf("[Server] Path rejected (files/get): %s -> %v", name, err)
			writeJSON(w, 400, map[string]string{"error": "invalid name"})
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name))
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// ═══ TLS 启动 ═══
	// 证书与 filestore 同级生成并持久化，指纹稳定供客户端 pinning
	exePath, _ := os.Executable()
	certDir := filepath.Dir(exePath)
	certFile, keyFile, fingerprint, err := ensureCert(certDir)
	if err != nil {
		log.Fatalf("[TLS] 证书初始化失败: %v", err)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		// 反慢速攻击：头阶段必须有超时。
		// 不设 Read/WriteTimeout 是刻意的：文件上传与运行时下载可能长时间传输，
		// 改用 ReadHeaderTimeout + MaxBytesReader(1MB/64MB) 兜住内存。
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("[Server] Starting HTTPS on port %d", port)
	log.Printf("[TLS] 证书: %s", certFile)
	log.Printf("[TLS] 证书 SHA-256 指纹: %s", fingerprint)
	log.Printf("[TLS] 将此指纹填入客户端 PINNED_CERT_SHA256 常量（StubCore.cpp）")
	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}

// isRuntimeZip 判断文件名是否为可下发的嵌入式运行时包名。
// 注意：原实现用 name[:6] 切片且守卫为 len(name) > 4，长度为 5 的
// 文件名会直接 panic（slice bounds out of range [:6] with length 5）。
func isRuntimeZip(name string) bool {
	low := strings.ToLower(name)
	if !strings.HasSuffix(low, ".zip") {
		return false
	}
	return strings.HasPrefix(low, "python") || strings.HasPrefix(low, "node")
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ═══ 安全工具 ═══

// safeJoin 将用户可控的 name 安全拼接在 base 下，阻止路径穿越。
// 规则：拒绝空值、绝对路径、盘符、反斜杠混淆、任何 ".." 序列，
// 并双重验证最终路径必须仍在 base 内。
func safeJoin(base, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}
	if len(name) > 255 {
		return "", errors.New("name too long")
	}
	// 统一分隔符后拒绝危险序列
	normalized := strings.ReplaceAll(name, "\\", "/")
	if strings.Contains(normalized, "..") {
		return "", errors.New("path traversal rejected")
	}
	if strings.ContainsAny(name, `:\"<>|`) { // Windows 保留字符 + 盘符冒号
		return "", errors.New("invalid characters in name")
	}
	if filepath.IsAbs(normalized) {
		return "", errors.New("absolute path rejected")
	}
	p := filepath.Join(base, filepath.FromSlash(normalized))
	// 双重验证：相对路径不允许逃出 base
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return "", errors.New("invalid path")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path escapes filestore")
	}
	return p, nil
}

// loadOrCreateAgentKey 加载或生成 agent 共享密钥。
// 优先级：环境变量 C2_AGENT_KEY > 可执行文件同级 agent.key 文件 > 新随机生成。
// 密钥持久化保证重启后不变，否则所有 agent 失联。
func loadOrCreateAgentKey() string {
	if v := os.Getenv("C2_AGENT_KEY"); v != "" {
		return v
	}
	exePath, err := os.Executable()
	if err == nil {
		keyFile := filepath.Join(filepath.Dir(exePath), "agent.key")
		if data, err := os.ReadFile(keyFile); err == nil {
			if v := strings.TrimSpace(string(data)); v != "" {
				return v
			}
		}
		b := make([]byte, 32)
		rand.Read(b)
		v := hex.EncodeToString(b)
		if err := os.WriteFile(keyFile, []byte(v), 0600); err != nil {
			log.Printf("[AgentKey] 警告: 密钥写入文件失败(%v)，重启后 agent 需重新获取密钥", err)
		}
		return v
	}
	// 兜底：仅本次进程有效的随机密钥
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// checkAgentAuth 校验 agent 请求（常数时间比较）。
// 仅按 hwid 校验该机器的独立密钥；引导密钥只允许在 register 接口使用
// （checkBootstrapAuth），避免引导密钥长期可用削弱 per-agent 隔离。
func checkAgentAuth(r *http.Request, hwid string, agents *AgentRegistry) bool {
	got := r.Header.Get("X-Agent-Key")
	if got == "" || hwid == "" || agents == nil {
		return false
	}
	if k := agents.AgentKey(hwid); k != "" {
		return subtle.ConstantTimeCompare([]byte(got), []byte(k)) == 1
	}
	return false
}

// checkBootstrapAuth 注册接口专用：仅接受引导密钥
func checkBootstrapAuth(r *http.Request, key string) bool {
	if key == "" {
		return false
	}
	got := r.Header.Get("X-Agent-Key")
	return subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1
}

// limitJSONBody 限制 JSON 请求体大小，防内存 DoS
func limitJSONBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
}

func checkAuth(r *http.Request, s *SessionManager) bool {
	for _, c := range r.Cookies() {
		if c.Name == "c2session" && s.Validate(c.Value) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cliClient CLI 专用 HTTP 客户端：默认连本机/受控环境，自签证书跳过系统信任链校验
var cliClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // CLI 运行在服务器本机，可接受
	},
}

// ========== CLI 子命令实现 ==========

func runAgentCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: c2-server agent list|info <hwid>")
		os.Exit(1)
	}
	base := getEnv("C2_API", "https://127.0.0.1:8080")
	token := login(base)
	if token == "" {
		fmt.Fprintln(os.Stderr, "登录失败")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		resp := getJSON(base+"/api/agents", token)
		fmt.Println(string(resp))
	case "info":
		if len(args) < 2 {
			fmt.Println("需提供 hwid")
			os.Exit(1)
		}
		resp := getJSON(base+"/api/agents", token)
		var agents []map[string]interface{}
		json.Unmarshal(resp, &agents)
		for _, a := range agents {
			if a["hwid"] == args[1] {
				fmt.Println(string(resp))
				return
			}
		}
		fmt.Println("{}")
	default:
		fmt.Println("未知子命令:", args[0])
	}
}

func runMcpCmd(args []string) {
	if len(args) < 3 {
		fmt.Println("用法: c2-server mcp call <hwid> <tool> <json-args>")
		os.Exit(1)
	}
	if args[0] != "call" {
		fmt.Println("仅支持 call 子命令")
		os.Exit(1)
	}
	base := getEnv("C2_API", "https://127.0.0.1:8080")
	token := login(base)
	if token == "" {
		fmt.Fprintln(os.Stderr, "登录失败")
		os.Exit(1)
	}
	hwid, tool, toolArgs := args[1], args[2], args[3]
	body := map[string]interface{}{
		"agent_hwid": hwid,
		"name":       tool,
		"arguments":  json.RawMessage(toolArgs),
	}
	resp := postJSON(base+"/api/mcp", token, body)
	// Parse request_id from response
	var mcpResp struct {
		OK        bool   `json:"ok"`
		RequestID string `json:"request_id"`
		Error     string `json:"error"`
	}
	json.Unmarshal(resp, &mcpResp)
	if !mcpResp.OK {
		fmt.Println(string(resp))
		os.Exit(1)
	}
	// Poll for result (max 30s)
	fmt.Fprintf(os.Stderr, "request_id=%s, waiting for result...\n", mcpResp.RequestID)
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		resultURL := base + "/api/mcp/result?request_id=" + mcpResp.RequestID
		resultResp := getJSON(resultURL, token)
		var pollResp struct {
			OK     bool            `json:"ok"`
			Status string          `json:"status"`
			Result json.RawMessage `json:"result"`
		}
		json.Unmarshal(resultResp, &pollResp)
		if pollResp.OK {
			fmt.Println(string(pollResp.Result))
			return
		}
	}
	fmt.Fprintln(os.Stderr, "超时（30秒）")
	os.Exit(1)
}

func login(base string) string {
	user := getEnv("C2_USER", "admin")
	pass := getEnv("C2_PASS", "changeme")
	data, _ := json.Marshal(map[string]string{"user": user, "pass": pass})
	req, _ := http.NewRequest("POST", base+"/api/login", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cliClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	// 从 Set-Cookie 拿 token
	for _, c := range resp.Cookies() {
		if c.Name == "c2session" {
			return c.Value
		}
	}
	return ""
}

func getJSON(url, token string) []byte {
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Cookie", "c2session="+token)
	}
	resp, err := cliClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data
}

func postJSON(url, token string, body interface{}) []byte {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Cookie", "c2session="+token)
	}
	resp, err := cliClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return out
}
