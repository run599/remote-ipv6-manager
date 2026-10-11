package main

import (
	"regexp"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/sha256"
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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

// ═══════════════════════════════════════════════
// RMM Server - Go rewrite
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
	clearIntegrity map[string]bool   // hwid -> 待下发的"解除安全隔离"指令（人工确认通道）

	// ── 自启动配置（见 state.go）──
	// 为什么挂在这里而不是另起一个 Store：密钥与 agent 记录本来就是同一份状态的
	// 两部分，分开存会出现"密钥存了但记录没存"的不一致，重启后表现为 401 但列表为空。
	stateDir   string
	stateKey   []byte
	stateDirty bool
	saveSignal chan struct{}
}

func NewAgentRegistry(dir string) *AgentRegistry {
	r := &AgentRegistry{
		agents:         make(map[string]*Agent),
		keys:           make(map[string]string),
		clearIntegrity: make(map[string]bool),
		stateDir:       dir,
		saveSignal:     make(chan struct{}, 1),
	}

	// 读回上次的状态。任何失败都只告警、不阻止启动 —— 服务端起得来比状态完整更重要。
	key, err := loadOrCreateStateKey(dir)
	if err != nil {
		log.Printf("[State] 状态密钥不可用(%v)，本次运行不自启动配置（重启后 agent 需重新登记）", err)
		return r
	}
	r.stateKey = key
	snap, err := loadStateFile(dir, key)
	if err != nil {
		log.Printf("[State] 读取状态失败: %v（按全新部署继续）", err)
		return r
	}
	for hwid, k := range snap.Keys {
		r.keys[hwid] = k
	}
	for hwid, a := range snap.Agents {
		cp := a
		cp.Online = false // 瞬时状态不自启动配置，等服务端收到心跳再点亮
		r.agents[hwid] = &cp
	}
	for hwid, v := range snap.ClearIntegrity {
		r.clearIntegrity[hwid] = v
	}
	log.Printf("[State] 已恢复状态: %d 个已登记 agent，%d 把 per-agent 密钥（文件 %s）",
		len(r.agents), len(r.keys), filepath.Join(dir, "state.json"))
	return r
}

// markDirty 打脏标记（调用方必须已持锁）
func (r *AgentRegistry) markDirty() { r.stateDirty = true }

// requestSave 请求后台立即落盘（非阻塞，通道满即已有待处理请求）
func (r *AgentRegistry) requestSave() {
	if r.saveSignal == nil {
		return
	}
	select {
	case r.saveSignal <- struct{}{}:
	default:
	}
}

// Snapshot 在锁内取一份状态副本（写盘在锁外做，避免 I/O 阻塞心跳）
func (r *AgentRegistry) Snapshot() stateSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := stateSnapshot{
		Keys:           make(map[string]string, len(r.keys)),
		Agents:         make(map[string]Agent, len(r.agents)),
		ClearIntegrity: make(map[string]bool, len(r.clearIntegrity)),
	}
	for k, v := range r.keys {
		snap.Keys[k] = v
	}
	for k, v := range r.agents {
		cp := *v
		cp.Online = false // 不把"在线"写进盘里
		snap.Agents[k] = cp
	}
	for k, v := range r.clearIntegrity {
		snap.ClearIntegrity[k] = v
	}
	return snap
}

// SaveNow 立即落盘。失败只告警：一次写盘失败不该影响服务本身。
func (r *AgentRegistry) SaveNow() {
	if r.stateKey == nil {
		return
	}
	r.mu.Lock()
	if !r.stateDirty {
		r.mu.Unlock()
		return
	}
	r.stateDirty = false
	snap := stateSnapshot{
		Keys:           make(map[string]string, len(r.keys)),
		Agents:         make(map[string]Agent, len(r.agents)),
		ClearIntegrity: make(map[string]bool, len(r.clearIntegrity)),
	}
	for k, v := range r.keys {
		snap.Keys[k] = v
	}
	for k, v := range r.agents {
		cp := *v
		cp.Online = false
		snap.Agents[k] = cp
	}
	for k, v := range r.clearIntegrity {
		snap.ClearIntegrity[k] = v
	}
	r.mu.Unlock()

	if err := saveStateFile(r.stateDir, r.stateKey, snap); err != nil {
		log.Printf("[State] 落盘失败: %v（已登记状态仍能靠下次保存补上）", err)
		// 写失败要恢复脏标记，否则这次变更永远不会被重试
		r.mu.Lock()
		r.stateDirty = true
		r.mu.Unlock()
	}
}

// RunAutoSave 后台批量落盘：收到信号立即写，否则每 5 秒兜一次。
// 不做成"每次心跳都写"是因为服务端跑在 eMMC 上，高频小写入会磨寿命。
func (r *AgentRegistry) RunAutoSave() {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-r.saveSignal:
		case <-ticker.C:
		}
		r.SaveNow()
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
	// 凭据签发必须立刻自启动配置：这里是"客户端从此能否认证"的分界点，
	// 慢一拍就可能出现"已发密钥但盘上没有"，重启即失联。
	r.markDirty()
	r.requestSave()
	return k
}

// RequestIntegrityClear 运维确认排查完毕后请求解除该 agent 的安全隔离
func (r *AgentRegistry) RequestIntegrityClear(hwid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[hwid]; !ok {
		return false
	}
	r.clearIntegrity[hwid] = true
	r.markDirty()
	r.requestSave()
	return true
}

// ConsumeIntegrityClear 取走一次解除指令（只下发一次）
func (r *AgentRegistry) ConsumeIntegrityClear(hwid string) bool {
	r.mu.Lock()
	r.markDirty()
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
	r.markDirty()
	r.requestSave()
}

// Remove 把受管端的**登记记录与 per-agent 密钥一并删除**。
// 为什么需要它：reauth 只删密钥（登记记录留着）；而运维要能把下线的/测试用的机器从列表里清掉，
// 否则面板上会一直堆着再也不会回来的死条目。
// 语义边界：这**不是拉黑** —— 该机若再启动，会回退用引导密钥重新登记，于是它又会出现。
// 想要"永久拒绝"得另做（改引导密钥 / 加黑名单），本次不做。
func (r *AgentRegistry) Remove(hwid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, hwid)
	delete(r.keys, hwid)
	r.markDirty()
	r.requestSave()
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
	r.markDirty()
	r.requestSave()
	log.Printf("[Agent] Registered: %s user=%s", hwid[:min(12, len(hwid))], user)
}

func (r *AgentRegistry) Heartbeat(hwid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[hwid]; ok {
		a.Online = true
		a.LastSeen = time.Now().UnixMilli()
		r.markDirty() // 交给后台批量落盘（心跳每 3 秒一次，不能每次都写 eMMC）
	}
}

// SetIntegrity 记录 agent 上报的完整性状态
func (r *AgentRegistry) SetIntegrity(hwid, integrity string) {
	// 完整性状态要自启动配置：它决定该 agent 是否处于安全隔离（暂停执行指令），
	// 重启后若丢失，会让一台"确认被集成"的机器悄悄恢复执行。
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
	// dir 非空时把会话表落盘：**服务端重启不该把所有客户端踢下线**。
	// 会话本来就是"到过期时间为止有效"，重启不该改变这个语义。
	dir string
	mu       sync.Mutex
	user     string
	pass     string
	sessions map[string]int64 // token -> 过期时间 (unix ms)
}

const sessionTTL = 24 * time.Hour

func NewSessionManager(user, pass string, dir string) *SessionManager {
	// （实测代价：面板静默 401 洪水 + 一直显示旧数据，而人看不出是登录掉了）
	s := &SessionManager{user: user, pass: pass, dir: dir, sessions: make(map[string]int64)}
	s.loadLocked()
	return s
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
	s.saveLocked()
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
		// 原来封顶 6（=64 分钟）：运维打错几次密码就被锁一小时，体验不可接受；
		// 而面板本就只在运维本机运行，暴力破解压力小，退避不必那么激进。
		if extra > 4 {
			extra = 4
		}
		lockFor := time.Minute << uint(extra)
		l.blocked[ip] = time.Now().Add(lockFor).UnixMilli()
		log.Printf("[Session] IP %s 登录失败 %d 次，锁定 %s", ip, l.fails[ip], lockFor)
	}
}

// RetryAfter 距解封还有多少秒（未锁定返回 0）。
// 供 429 回包使用：面板要能把"还要等多久"直接告诉用户，
// 否则用户只会反复重试，把指数退避越推越长。
func (l *LoginLimiter) RetryAfter(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blocked[ip]
	if !ok {
		return 0
	}
	sec := int((until - time.Now().UnixMilli()) / 1000)
	if sec < 0 {
		return 0
	}
	return sec
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
	ackTimeout    = 90 * time.Second  // 投出后多久没回报就视为"没执行完" 重投 
	maxAttempts   = 3                 // 最多投递次数（超过判失败并**告知调用方** ）
	queueDeadline = 30 * time.Minute  // 单条指令的最终截止（避免无限重投 ）
)

type Command struct {
	RequestID string
	HWID      string
	Method    string
	Params    string
	Enqueued  int64 // unix ms，超时未取走即丢弃（避免上线后执行陈旧指令）
	// ── 2026-10-11 队列升级：可靠性字段 ──
	Attempts int    // 已投递次数（含 inflight 中这一次 ）
	LastSent int64  // 最近一次投递时间（unix ms ）
	Deadline int64  // 最终截止：超过即判失败（避免无限重投 ）
}

type qinflight struct {
	cmd      Command
	sentAt   int64
	attempts int
}

type CommandQueue struct {
	mu        sync.Mutex
	cmds      map[string][]Command
	inflight  map[string]*qinflight // reqID  待确认
	failed    map[string]resultEntry
	results   map[string]resultEntry
	owner     map[string]ownerEntry
	path      string // 落盘路径（"" = 不落盘  便于测试）
	dirty     bool
	statSent  int64 // 累计投递次数（面板可见 ）
	statRetry int64
	statFail  int64
}

func NewCommandQueue() *CommandQueue {
	return &CommandQueue{
		cmds:     make(map[string][]Command),
		inflight: make(map[string]*qinflight),
		failed:   make(map[string]resultEntry),
		results:  make(map[string]resultEntry),
		owner:    make(map[string]ownerEntry),
	}
}

func (q *CommandQueue) AttachPersistence(path string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.path = path
	q.loadLocked()
}

type queueDisk struct {
	Cmds     map[string][]Command     `json:"cmds"`
	Inflight map[string]*qinflight    `json:"inflight"`
	Failed   map[string]resultEntry   `json:"failed"`
	Results  map[string]resultEntry   `json:"results"`
	Owner    map[string]ownerEntry    `json:"owner"`
	StatSent int64                    `json:"stat_sent"`
	StatRetry int64                   `json:"stat_retry"`
	StatFail int64                    `json:"stat_fail"`
}

func (q *CommandQueue) loadLocked() {
	if q.path == "" {
		return
	}
	b, err := os.ReadFile(q.path)
	if err != nil || len(b) == 0 {
		return
	}
	var d queueDisk
	if json.Unmarshal(b, &d) != nil {
		log.Printf("[Queue] 队列文件损坏，忽略（从空队列开始）: %s", q.path)
		return
	}
	if d.Cmds != nil {
		q.cmds = d.Cmds
	}
	if d.Inflight != nil {
		q.inflight = d.Inflight
	}
	if d.Failed != nil {
		q.failed = d.Failed
	}
	if d.Results != nil {
		q.results = d.Results
	}
	if d.Owner != nil {
		q.owner = d.Owner
	}
	q.statSent, q.statRetry, q.statFail = d.StatSent, d.StatRetry, d.StatFail
	n := 0
	for _, v := range q.cmds {
		n += len(v)
	}
	log.Printf("[Queue] 已恢复队列：待执行 %d 条、执行中 %d 条、失败 %d 条（文件 %s）", n, len(q.inflight), len(q.failed), q.path)
	for _, f := range q.inflight {
		c := f.cmd
		q.cmds[c.HWID] = append(q.cmds[c.HWID], c)
	}
	q.inflight = make(map[string]*qinflight)
	q.dirty = true
}

func (q *CommandQueue) saveLocked() {
	if q.path == "" || !q.dirty {
		return
	}
	d := queueDisk{Cmds: q.cmds, Inflight: q.inflight, Failed: q.failed,
		Results: q.results, Owner: q.owner,
		StatSent: q.statSent, StatRetry: q.statRetry, StatFail: q.statFail}
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	tmp := q.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		if os.Rename(tmp, q.path) == nil {
			q.dirty = false
		}
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
	total += len(q.inflight)
	if total >= maxQueueTotal {
		return "", fmt.Errorf("global queue full (max %d)", maxQueueTotal)
	}
	reqID := "req-" + randomHex(16) // 不可预测，避免被猜出他人 request_id
	now := time.Now()
	q.cmds[hwid] = append(q.cmds[hwid], Command{
		RequestID: reqID, HWID: hwid, Method: method, Params: params,
		Enqueued: now.UnixMilli(), Deadline: now.Add(queueDeadline).UnixMilli(),
	})
	q.owner[reqID] = ownerEntry{hwid: hwid, deadline: now.Add(resultTTL + queueDeadline).UnixMilli()}
	q.dirty = true
	return reqID, nil
}

func (q *CommandQueue) failLocked(reqID, hwid, reason string) {
	msg := fmt.Sprintf(`{"ok":false,"failed":true,"reason":%q}`, reason)
	q.results[reqID] = resultEntry{value: msg, deadline: time.Now().Add(resultTTL).UnixMilli()}
	q.failed[reqID] = resultEntry{value: msg, deadline: time.Now().Add(resultTTL).UnixMilli()}
	delete(q.owner, reqID)
	q.statFail++
	q.dirty = true
	log.Printf("[Queue] 指令失败 reqID=%s hwid=%s 原因=%s", reqID, hwid, reason)
}

func (q *CommandQueue) Dequeue(hwid string) (Command, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cmds, ok := q.cmds[hwid]
	if !ok || len(cmds) == 0 {
		delete(q.cmds, hwid)
		return Command{}, false
	}
	now := time.Now().UnixMilli()
	for len(cmds) > 0 && (now-cmds[0].Enqueued > commandTTL.Milliseconds() || (cmds[0].Deadline > 0 && now > cmds[0].Deadline)) {
		cmd := cmds[0]
		q.failLocked(cmd.RequestID, hwid, "指令过期未被执行（受管端离线过久）")
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
	cmd.Attempts++
	cmd.LastSent = now
	q.inflight[cmd.RequestID] = &qinflight{cmd: cmd, sentAt: now, attempts: cmd.Attempts}
	q.statSent++
	q.dirty = true
	return cmd, true
}

func (q *CommandQueue) Sweep() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(time.Now().UnixMilli())
}

func (q *CommandQueue) sweepOldUnused() {
	now := time.Now().UnixMilli()
	for reqID, f := range q.inflight {
		if now-f.sentAt < ackTimeout.Milliseconds() {
			continue
		}
		c := f.cmd
		delete(q.inflight, reqID)
		if f.attempts >= maxAttempts || (c.Deadline > 0 && now > c.Deadline) {
			q.failLocked(reqID, c.HWID, fmt.Sprintf("已投递 %d 次仍未回报结果（超时 %s/次）", f.attempts, ackTimeout))
			continue
		}
		c.LastSent = now
		q.cmds[c.HWID] = append([]Command{c}, q.cmds[c.HWID]...)
		q.owner[reqID] = ownerEntry{hwid: c.HWID, deadline: now + (resultTTL + queueDeadline).Milliseconds()}
		q.statRetry++
		q.dirty = true
		log.Printf("[Queue] 指令超时未回报，重新入队 reqID=%s hwid=%s 第 %d 次", reqID, c.HWID, f.attempts)
	}
	for k, e := range q.failed {
		if now > e.deadline {
			delete(q.failed, k)
			q.dirty = true
		}
	}
}

func (q *CommandQueue) QueueView(hwid string) map[string]interface{} {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().UnixMilli()
	pending := []map[string]interface{}{}
	inflight := []map[string]interface{}{}
	for h, lst := range q.cmds {
		if hwid != "" && h != hwid {
			continue
		}
		for i, c := range lst {
			pending = append(pending, map[string]interface{}{
				"request_id": c.RequestID, "hwid": h, "method": c.Method,
				"age_ms": now - c.Enqueued, "attempts": c.Attempts, "pos": i,
			})
		}
	}
	for _, f := range q.inflight {
		if hwid != "" && f.cmd.HWID != hwid {
			continue
		}
		inflight = append(inflight, map[string]interface{}{
			"request_id": f.cmd.RequestID, "hwid": f.cmd.HWID, "method": f.cmd.Method,
			"sent_ms_ago": now - f.sentAt, "attempts": f.attempts,
		})
	}
	failed := []map[string]interface{}{}
	for id, e := range q.failed {
		failed = append(failed, map[string]interface{}{"request_id": id, "result": e.value})
	}
	return map[string]interface{}{
		"ok": true, "pending": pending, "inflight": inflight, "failed": failed,
		"counts": map[string]int{"pending": len(pending), "inflight": len(inflight), "failed": len(failed)},
		"stats":  map[string]int64{"sent": q.statSent, "retry": q.statRetry, "fail": q.statFail},
		"policy": map[string]interface{}{"ack_timeout": ackTimeout.String(), "max_attempts": maxAttempts,
			"command_ttl": commandTTL.String(), "deadline": queueDeadline.String()},
	}
}

// StoreResult 落库结果；hwid 必须与该 requestId 的归属一致，
// 否则拒绝（防止某个已异常 agent 用猜到的 request_id 污染他机结果）
func (q *CommandQueue) StoreResult(reqID, hwid, result string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if o, ok := q.owner[reqID]; ok && o.hwid != hwid {
		return fmt.Errorf("request_id %s 不属于该 agent", reqID)
	}
	q.results[reqID] = resultEntry{value: result, deadline: time.Now().Add(resultTTL).UnixMilli()}
	delete(q.owner, reqID)
	delete(q.inflight, reqID) //  收到结果  真正清掉（"报完成了才清" ）
	q.dirty = true
	return nil
}

// OwnerOf 返回某个 requestId 归属的 hwid（"" = 未知）。
func (q *CommandQueue) OwnerOf(reqID string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e, ok := q.owner[reqID]; ok {
		return e.hwid
	}
	if f, ok := q.inflight[reqID]; ok {
		return f.cmd.HWID
	}
	return ""
}

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
	q.sweepLocked(now)
	q.saveLocked()
}

func (q *CommandQueue) sweepLocked(now int64) {
	for reqID, f := range q.inflight {
		if now-f.sentAt < ackTimeout.Milliseconds() {
			continue
		}
		c := f.cmd
		delete(q.inflight, reqID)
		if f.attempts >= maxAttempts || (c.Deadline > 0 && now > c.Deadline) {
			q.failLocked(reqID, c.HWID, fmt.Sprintf("已投递 %d 次仍未回报结果（每次超时 %s）", f.attempts, ackTimeout))
			continue
		}
		c.LastSent = now
		q.cmds[c.HWID] = append([]Command{c}, q.cmds[c.HWID]...)
		q.owner[reqID] = ownerEntry{hwid: c.HWID, deadline: now + (resultTTL + queueDeadline).Milliseconds()}
		q.statRetry++
		q.dirty = true
		log.Printf("[Queue] 指令超时未回报，重新入队 reqID=%s hwid=%s 第 %d 次", reqID, c.HWID, f.attempts)
	}
	for k, e := range q.failed {
		if now > e.deadline {
			delete(q.failed, k)
			q.dirty = true
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
	port := getEnvInt("RMM_PORT", 8080)
	user := getEnv("RMM_USER", "admin")
	pass := getEnv("RMM_PASS", "changeme")

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
			fmt.Println("RMM Server v1.0.0")
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
	fmt.Println(`RMM Server - 命令行用法:
  rmm-server serve [--port N] [--user U] [--pass P]  启动服务端
  rmm-server agent list                                              列出在线 Agent
  rmm-server agent info <hwid>                                       查看 Agent 详情
  rmm-server mcp call <hwid> <tool> <json-args>                      调用 MCP 工具（同步等待结果）
  rmm-server version                                                 显示版本
  rmm-server help                                                    显示帮助

环境变量兜底: RMM_PORT RMM_USER RMM_PASS RMM_AGENT_KEY
示例:
  rmm-server serve --port 8080
  rmm-server agent list
  rmm-server mcp call BCA92F84 execute '{"command":"whoami"}'`)
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

	stateDir := serverStateDir()
	agents := NewAgentRegistry(stateDir)
	go agents.RunAutoSave() // 后台批量落盘（见 RunAutoSave 的说明）
	screen := NewScreenHub()
	// 状态密钥：工件台账 / 期望态都用它加密落盘。
	// 单独一个文件而不是塞进 stateSnapshot：任务读写成频率与 agent 心跳差好几个数量级，
	// 混在一起会让每次心跳都可能触发任务文件的整体重写。
	taskKey, taskKeyErr := loadOrCreateStateKey(stateDir)
	if taskKeyErr != nil {
		log.Printf("[State] 无法取得状态密钥，状态将不自启动配置: %v", taskKeyErr)
		taskKey = []byte("00000000000000000000000000000000")
	}
	// 外置工件的密钥登记表（见 artifacts.go）。
	// 与任务共用同一把 state.key，但独立文件：工件登记是低频写、且与任务无关。
	artifacts := NewArtifactHub(stateDir, taskKey)
	// 声明期望态 + 受管端状态上报（见 desired.go）。
	// 同样共用 state.key、独立文件：低频写、与任务/工件无关。
	desired := NewDesiredHub(stateDir, taskKey)
	sessions := NewSessionManager(user, pass, stateDir)
	// 而它需要的 filestoreDir 要到更下面才定义出来。Go 要求声明在前，
	// 所以不能就地 :=（我第一次就是就地写的，报 undefined: pluginHost）。
	var pluginHost *PluginHost
	cmds := NewCommandQueue()
	cmds.AttachPersistence(filepath.Join(stateDir, "queue.json"))
	limiter := NewLoginLimiter()

	// agent 共享密钥：所有 agent 接口必须携带 X-Agent-Key 头
	agentKey := loadOrCreateAgentKey()
	log.Printf("[AgentKey] 共享密钥已加载（客户端通过环境变量 R6M_AGENT_KEY 或 --agent-key 传入）")

	// 默认口令告警
	if user == "admin" && pass == "changeme" {
		log.Printf("[安全警告] 当前使用默认口令 admin/changeme！请通过 --pass 或 RMM_PASS 立即修改")
	}

	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			agents.Cleanup()
			sessions.Cleanup()
			cmds.Cleanup()
			limiter.Cleanup()
			screen.Cleanup()
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
			// 明确告诉调用方"这是限流锁定，不是密码错"，并给出剩余秒数。
			// 原实现只回一句 too many failures，面板侧无法区分 401/429，
			// 用户看到"密码是对的却登不上"只会反复重试（越试锁越久）。
			retry := limiter.RetryAfter(clientIP)
			if retry > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
			}
			log.Printf("[Session] 拒绝登录：IP %s 处于锁定中，剩余 %d 秒", clientIP, retry)
			writeJSON(w, 429, map[string]interface{}{
				"error":       "too_many_attempts",
				"retry_after": retry,
				"message":     "登录失败次数过多，已临时锁定",
			})
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
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Health —— 不需要任何凭据的最小探针。
	// 客户端在发送任何密钥之前先打这个接口完成 TLS 标识校验，
	// 这样标识不匹配时凭据根本不会离开本机。
		mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, healthBody())
	})

	// Integrity clear —— 运维确认排查完毕后解除该 agent 的安全隔离
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
		log.Printf("[Server] 运维请求解除安全隔离: %s（将在其下次心跳的下一次 poll 下发）", hwid)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Agent reauth —— 运维吊销某 hwid 的 per-agent 密钥，允许其用引导密钥重新登记。
	mux.HandleFunc("/api/agent/reauth", func(w http.ResponseWriter, r *http.Request) {
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
	// 移除受管端（从面板列表清掉；连同它的期望态一起清）
	// 为什么连期望态也要清：否则会留下"孤儿策略" —— 服务端还记着这台的策略，
	// 而它已经不在列表里了，既看不见也管不着。
	mux.HandleFunc("/api/agents/remove", func(w http.ResponseWriter, r *http.Request) {
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
		agents.Remove(hwid)
		desired.Set(hwid, nil)
		desired.ClearPending(hwid)
		log.Printf("[Server] 移除受管端 %s（登记记录 + per-agent 密钥 + 期望态）", hwid)
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "removed": hwid,
			"note": "已从列表移除并清掉期望态；该机若再次运行，会用引导密钥重新登记",
		})
	})

	mux.HandleFunc("/api/queue", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		v := cmds.QueueView(hwid)
		ds := []map[string]interface{}{}
		scope := []string{hwid}
		if hwid == "" {
			scope = nil
			for _, a := range agents.GetAll() {
				scope = append(scope, a.HWID)
			}
		}
		for _, h := range scope {
			rev := desired.Rev(h)
			if rev <= 0 {
				continue
			}
			row := map[string]interface{}{"hwid": h, "desired_rev": rev}
			if st := desired.Status(h); st != nil {
				row["applied_rev"] = st.DesiredRev
				row["drift"] = st.DesiredDrift
				row["converged"] = len(st.DesiredDrift) == 0
				if st.SeenMs > 0 {
					row["seen_ms_ago"] = time.Now().UnixMilli() - st.SeenMs
				}
			}
			if p := desired.PendingFor(h); p != nil {
				row["pending_revert_at_ms"] = p.AtMs
				row["pending_revert_label"] = p.Label
			}
			ds = append(ds, row)
		}
		v["desired"] = ds
		writeJSON(w, 200, v)
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]int{"agents_online": agents.OnlineCount(), "agents_total": len(agents.GetAll())})
	})

	// Agents
	mux.HandleFunc("/api/gate/code", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		raw, err := os.ReadFile(gateSecretPath)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{
				"ok": false, "has_secret": false,
				"error": "服务端没有 gate.secret（路径 " + gateSecretPath + "）：" + err.Error(),
			})
			return
		}
		now := time.Now().Unix()
		step5 := now / 300
		pwd, ok5 := gatePwd(string(raw), step5)
		step30 := now / 30
		code, ok30 := gateTotp(string(raw), step30)
		if !ok5 || !ok30 {
			writeJSON(w, 200, map[string]interface{}{
				"ok": false, "has_secret": true,
				"error": "gate.secret 内容不是合法 hex",
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "has_secret": true,
			"user":  "r6mop",
			"pwd":   pwd,
			"pwd_code": pwd,
			"pwd_remaining": 300 - (now % 300), "pwd_step": step5,
			"code":  code,
			"remaining": 30 - (now % 30), "step": step30,
		})
	})

	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		// 附带"使用人申报了完成、待管理员核验"的标记。
		// 面板的受管端列表每 5 秒拉一次这里，所以不需要管理员主动操作 ——
		// 使用人按下按钮后，管理员侧列表上会直接出现待检查标记。
		raw, _ := json.Marshal(agents.GetAll())
		var list []map[string]interface{}
		if err := json.Unmarshal(raw, &list); err != nil {
			writeJSON(w, 200, agents.GetAll())
			return
		}
		for i := range list {
			hw, _ := list[i]["hwid"].(string)
			if hw == "" {
				continue
			}
			// 运行事实上报：是不是管理员、当前在哪个端点、失败几次、达成到哪个 rev。
			// 这些字段是"为什么这条指令没生效"的直接答案。
			if st := desired.Status(hw); st != nil {
				list[i]["admin"] = st.Admin
				list[i]["endpoint"] = st.Endpoint
				list[i]["endpoint_index"] = st.EndpointIndex
				list[i]["endpoint_total"] = st.EndpointTotal
				list[i]["endpoint_fails"] = st.EndpointFails
				list[i]["applied_rev"] = st.DesiredRev
			// 偏离详情一并透出：面板据此显示"哪一项被改了"，而不是只看到"有偏离"
			if len(st.DesiredDrift) > 0 {
				list[i]["desired_drift"] = st.DesiredDrift
			}
				list[i]["status_ms"] = st.SeenMs
			}
			if r := desired.Rev(hw); r > 0 {
				list[i]["desired_rev"] = r
			}
		}
		writeJSON(w, 200, list)
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
		// 绝不允许"持有引导密钥就给已登记 hwid 补发密钥"，否则任一异常客户端
		// 都能冒名接管其他节点（引导密钥分发在每台客户端的 r6m.ini 里）。
		presented := r.Header.Get(hdrAgentKey)
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
				log.Printf("[Server] 拒绝身份重复注册: hwid=%s 已登记，调用方只提供了引导密钥（ip=%s）", hwid, r.RemoteAddr)
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
			// 完整性上报（IntegrityCheck 三段式之二）
			if integrity, ok := body["integrity"].(string); ok && integrity != "" {
				agents.SetIntegrity(hwid, integrity)
				if integrity != "ok" {
					// 醒目告警：运维无需盯日志，agent 列表即见标红状态
					log.Printf("[!!完整性告警!!] agent=%s 状态=%s —— 该端点疑似被集成，建议停止对其下发指令并排查", hwid, integrity)
				}
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

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
			// 运维已确认排查完毕：下发一次解除安全隔离（IntegrityCheck 三段式的复位通道）
			resp["clear_integrity"] = true
			log.Printf("[Server] 已向 %s 下发解除安全隔离指令", hwid)
		}
		// 屏幕监控：把当前会话的采集参数带回给受管端。
		// 受管端据此启动/停止采集线程（没有这个字段 = 不要采集）。
		// 这是整条实时看屏链路的"控制面"：唯一的开关就在这里，
		// 只发"变化"的话重启后就永远收不到锁定状态 —— 使用人只要重启一次就兼容处理了管控。
		// 状态由服务端计算，受管端无法本地伪造，这是整套防篡改的根基。

		// 必须每轮都发（不能只在 rev 变化时发）：受管端可能重启，只发变化它就永远不知道目标。
		// r 是 if 里声明的局部变量 —— 搬这段代码时必须连外层 if 一起搬，
		// 否则 r 会落到 handler 的 *http.Request 参数上（同名，编译仍通过，但响应会被代码化坏）。
		if r := desired.Rev(hwid); r > 0 {
			resp["desired_rev"] = r
		}

		// ── P2 通用状态通道 ──
		// 内核**不解释**这里的内容，只把插件写下的状态原样带给受管端。
		// 这正是"内核无业务"的落地：会话锁定只是其中一个 key，内核根本不认识它。
		// 谁写的、写了什么，看 /api/plugins/audit 的 state 就对得上。
		if kv := pluginHost.KV(); len(kv) > 0 {
			resp["state"] = kv
		}

		if scale, interval, ok := screen.Spec(hwid); ok {
			resp["screen_stream"] = map[string]interface{}{
				"scale":       scale,
				"interval_ms": interval,
				"format":      "png",
			}
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

	// ═══ 屏幕监控（实时看屏）═══
	// 控制面：面板开关监控会话；数据面：/api/agent/frame 上行、/api/screen/latest 下行。
	// 设计取舍见 screen.go 顶部说明（为什么不能让面板反复调截图工具）。

	// 面板：开始/更新监控
	mux.HandleFunc("/api/screen/start", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitJSONBody(w, r)
		var body struct {
			HWID       string `json:"hwid"`
			Scale      int    `json:"scale"`
			IntervalMs int    `json:"interval_ms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.HWID == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		if body.Scale == 0 {
			body.Scale = 4
		}
		if body.IntervalMs == 0 {
			body.IntervalMs = 400
		}
		screen.Start(body.HWID, body.Scale, body.IntervalMs)
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "scale": body.Scale, "interval_ms": body.IntervalMs,
		})
	})

	// 面板：停止监控
	mux.HandleFunc("/api/screen/stop", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitJSONBody(w, r)
		var body struct {
			HWID string `json:"hwid"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.HWID == "" {
			body.HWID = r.URL.Query().Get("hwid")
		}
		ok := screen.Stop(body.HWID)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "was_active": ok})
	})

	// 面板：取最新一帧（按面板自己的显示节奏轮询；服务端只留最新帧，不排队）
	mux.HandleFunc("/api/screen/latest", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		b64, fmtName, fw, fh, seq, ageMs, ok := screen.Latest(hwid)
		if !ok {
			// 会话不存在（没开始过 / 已停止 / 静默超时被清理）
			writeJSON(w, 404, map[string]string{"error": "no active screen session"})
			return
		}
		if seq == 0 {
			// 会话在但首帧还没到：给面板一个明确的"等待中"，而不是让它以为出错
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "seq": 0, "waiting": true, "age_ms": 0,
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "seq": seq, "format": fmtName,
			"width": fw, "height": fh, "age_ms": ageMs,
			"image_base64": b64,
		})
	})

	// 受管端：上行走廊（每帧一 POST，覆盖式写入，不做队列）
	mux.HandleFunc("/api/agent/frame", func(w http.ResponseWriter, r *http.Request) {
		reqHWID := r.Header.Get(hdrAgentHWID)
		if !checkAgentAuth(r, reqHWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		// 单帧最大 8MB：base64 后约 6MB 原始数据，远超任何合理分辨率。
		// 这里必须用**独立上限**而不是 limitJSONBody(1MB)——
		// 后者会像 /api/agent/result 当初那样在 1MB 处停止读取、把连接僵住。
		limitJSONBodyFrame(w, r, screenMaxFrameBytes)
		var body struct {
			Seq         uint64 `json:"seq"`
			Format      string `json:"format"`
			Width       int    `json:"width"`
			Height      int    `json:"height"`
			ImageBase64 string `json:"image_base64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if body.ImageBase64 == "" {
			writeJSON(w, 400, map[string]string{"error": "empty frame"})
			return
		}
		if !screen.StoreFrame(reqHWID, body.ImageBase64, body.Format, body.Width, body.Height, body.Seq) {
			// 没有会话：受管端可能刚收到停止指令但还在传最后一帧，属正常情况，
			// 回 200 让它继续自己的节奏（回错误会诱使客户端重试，反而浪费带宽）
			writeJSON(w, 200, map[string]bool{"ok": true, "dropped": true})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ═══ 任务管控：任务 / 解锁 ═══
	// 鉴权：面板会话 cookie。校验命令由面板经 MCP 中继发到受管端执行，
	// 服务端只记录"通过"这一事实（不在服务端执行命令，见 tasks.go 说明）。


	// 任务等级表：面板与 CLI 都从这里读，避免各自硬编码导致"等级对应多久"不一致





	// 反向通道：受管端（屏幕锁定上的按钮）申报"我已完成"，等管理员核验。
	// 鉴权用 per-agent 密钥 —— 使用人没有这把密钥，所以无法伪造别人的申报，
	// 也无法在没屏幕锁定的机器上乱发。这条消息本身不带任何解锁权力。

	// ═══ 外置工件：密钥登记 ═══
	// 受管端投放完工具后调这里：把"客户端签发的 key"与"文件/进程事实"一起登记。
	// 为什么 key 由受管端签发：它才是唯一知道文件实际落在哪、以什么进程跑起来的一方。
	mux.HandleFunc("/api/artifact/register", func(w http.ResponseWriter, r *http.Request) {
		reqHWID := r.Header.Get(hdrAgentHWID)
		if !checkAgentAuth(r, reqHWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitJSONBody(w, r)
		var a Artifact
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil || a.Key == "" || a.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "missing key/name"})
			return
		}
		if a.HWID == "" {
			a.HWID = reqHWID
		}
		if a.HWID != reqHWID {
			// 只允许登记自己这台机器上的工件，避免一台受管端替别的机器登记
			writeJSON(w, 403, map[string]string{"error": "hwid mismatch"})
			return
		}
		replaced, err := artifacts.Register(&a)
		if err != nil {
			// 409：明确告诉受管端"这把钥匙是别人的"，让它改用正确密钥或先作废。
			// 静默改嫁会直接导致"钥匙对应哪个文件"说不清，也就是所谓的投反。
			log.Printf("[Artifact] 拒绝登记（密钥冲突）: %v", err)
			writeJSON(w, 409, map[string]interface{}{"error": err.Error(), "conflict": true})
			return
		}
		out := map[string]interface{}{"ok": true, "key": a.Key}
		if replaced != nil {
			// 同名换钥匙：把作废的旧 key 回给管理端，让它更新映射而不是留两条记录
			out["replaced_key"] = replaced.Key
			out["replaced_note"] = "同一文件的原登记已作废（本地配置重建）"
		}
		writeJSON(w, 200, out)
	})

	// 受管端投放前先查：这台机器上这个文件原来用的是哪把钥匙。
	// 有了它，"key 的权威来源"就是服务端 —— 本地 ini 丢失也不会换新钥匙，
	// 避免同一个文件出现两条 key 记录（那是投反的典型成因）。
	mux.HandleFunc("/api/artifact/resolve", func(w http.ResponseWriter, r *http.Request) {
		reqHWID := r.Header.Get(hdrAgentHWID)
		if !checkAgentAuth(r, reqHWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		name := r.URL.Query().Get("name")
		a, ok := artifacts.Resolve(reqHWID, name)
		if !ok {
			writeJSON(w, 200, map[string]interface{}{"found": false})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"found": true, "key": a.Key, "name": a.Name,
			"sha256": a.SHA256, "size": a.Size, "path": a.Path,
		})
	})

	// 管理端查"哪把钥匙对应哪个工件"（文件/进程/pid/标识）
	mux.HandleFunc("/api/artifact/list", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "artifacts": artifacts.List(r.URL.Query().Get("hwid")),
		})
	})

	// 只读的锁定状态查询（**工件密钥鉴权**）。
	// 外置工具与主受管端同时拉会让命令被抢走。这里只读，不碰队列。

	// 家长设置/修改口令（面板鉴权）

	// 屏幕锁定上输口令解锁（受管端鉴权）。
	// 这是"单机场景下管理员唯一的出路"：屏幕锁定盖住桌面时，管理端打不开，
	// 管理员只能在这个界面上输入口令。校验在服务端做，口令不落客户端。

	// 授权解锁：minutes<=0 表示立即恢复锁定

	// Agent result — per-agent 密钥（按请求头 X-Agent-HWID 认证）
	mux.HandleFunc("/api/agent/result", func(w http.ResponseWriter, r *http.Request) {
		// result 的 body 里只有 request_id 没有 hwid，hwid 从头里取
		reqHWID := r.Header.Get(hdrAgentHWID)
		if !checkAgentAuth(r, reqHWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitResultBody(w, r) // 截图结果是 MB 级 base64，不能用 1 MB 的 limitJSONBody
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			// 超限要明确回 413：原来退化成含糊的 400 "bad request"，
			// 现场只能看到面板轮询到超时，完全指不出是体积问题。
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				log.Printf("[Server] 结果体超限: hwid=%s limit=%d —— 调大 RMM_MAX_RESULT_BYTES，或让客户端降低截图分辨率(scale)",
					reqHWID, resultBodyLimit)
				writeJSON(w, 413, map[string]string{
					"error": "result too large",
					"limit": strconv.FormatInt(resultBodyLimit, 10),
				})
				return
			}
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

		// ── 离线快速失败 ──
		// 受管端离线时，指令入队后 /api/mcp/result 会一直回 pending，
		// 调用方按 500ms 轮询要等满 60 秒（截图 180 秒）。而面板的 MCP 桥
		// 在等待期间**拒绝一切其它调用**（「上一个调用尚未完成」）——
		// 用户看到的现象就是"登录进去了但点什么都没反应"，而且完全不知道
		// 是受管端没上线。所以交互式调用一律立即失败并说明原因。
		// 确需"等它上线再执行"的走 ?queue_if_offline=1。
		{
			online, lastSeen := false, int64(0)
			for _, a := range agents.GetAll() {
				if a.HWID == body.AgentHWID {
					online, lastSeen = a.Online, a.LastSeen
					break
				}
			}
		if !online && r.URL.Query().Get("fail_fast") == "1" {
				ago := ""
				if lastSeen > 0 {
					d := (time.Duration(time.Now().UnixMilli()-lastSeen) * time.Millisecond).Round(time.Second)
					ago = "（最后在线 " + d.String() + " 前）"
				}
				log.Printf("[Server] MCP 拒绝：受管端离线 hwid=%s name=%s", body.AgentHWID, body.Name)
				writeJSON(w, 200, map[string]interface{}{
					"ok":    false,
					"code":  "AGENT_OFFLINE",
					"error": "受管端离线" + ago + "，这条指令**未入队**（?fail_fast=1 快速失败）—— 去掉该参数即会排队等它上线",
				})
				return
			}
		}

		// 「列出可用工具」不是一次工具调用 —— tools/list 是**插件协议方法**，
		// 没有任何插件「提供」它。面板原来把它塞进 tools/call 的 name 里，
		// 于是管理端的工具下拉永远是空的（用户看到的就是「没暴露任何命令」）。
		// 这里识别出来，按 method 原样下发 —— 受管端本来就实现了这条聚合。
		method, rpcParams := "tools/call", ""
		if body.Name == "tools/list" {
			method, rpcParams = "tools/list", "{}"
		} else {
			b, _ := json.Marshal(map[string]interface{}{"name": body.Name, "arguments": body.Arguments})
			rpcParams = string(b)
		}
		reqID, err := cmds.Enqueue(body.AgentHWID, method, rpcParams)
		if err != nil {
			log.Printf("[Server] 入队失败: %v", err)
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[Server] MCP enqueue for %s: reqID=%s name=%s", body.AgentHWID, reqID, body.Name)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "request_id": reqID})
	})

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
			// 还没结果 —— 顺便判断受管端还在不在。
			// 只看 a.Online 不够：它的过期依赖 Cleanup（LastSeen 超 60 秒才判离线），
			// 所以"刚断线几秒"的窗口里它仍是 true，调用方会把 60 秒等满。
			// 这里加一道 LastSeen 时效判据（15 秒 ≈ 连丢 3~5 拍心跳）。
			hw := cmds.OwnerOf(reqID)
			gone := false
			if hw != "" {
				gone = true // 归属已知但没找到该 agent 记录  视为不在线
				for _, a := range agents.GetAll() {
					if a.HWID == hw {
						gone = !a.Online ||
							(time.Now().UnixMilli()-a.LastSeen) > 15000
						break
					}
				}
			}
			if gone {
				log.Printf("[Server] 结果轮询中止：受管端已离线 req=%s hwid=%s", reqID, hw)
				writeJSON(w, 200, map[string]interface{}{
					"ok":   false,
					"code": "AGENT_OFFLINE",
					"error": "受管端已离线，这条指令不会被执行 —— 已停止等待（先让受管端上线）",
				})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"ok": false, "status": "pending"})
		}
	})

	// ═══ File Store path ═══
	// 优先用环境变量，否则用可执行文件同级目录下的 filestore/
	filestoreDir := func() string {
		if v := os.Getenv("RMM_FILESTORE"); v != "" {
			return v
		}
		exePath, _ := os.Executable()
		return filepath.Join(filepath.Dir(exePath), "filestore")
	}()



	// ── 临时临时授权的另一端：到点自动恢复 ──
	// 每 5 秒看一次有没有到点的预约；到点就把那台机的期望态恢复成"临时授权前的快照"。
	// 放在这里是因为此时 desired 已就绪；用 goroutine 以免拖慢启动。
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			for _, p := range desired.DuePendings(time.Now().UnixMilli()) {
				// ① **先写回文件字节**。顺序不能反：条目恢复只改"指向谁"，
				restored, removed, failed := 0, 0, 0
				for _, f := range p.Files {
					full := filepath.Join(filestoreDir, f.Name)
					if !f.Existed {
						if err := os.Remove(full); err == nil || os.IsNotExist(err) {
							removed++
						}
						continue
					}
					tmp := full + ".tmp"
					if err := os.WriteFile(tmp, f.Bytes, 0644); err != nil {
						failed++
						continue
					}
					if err := os.Rename(tmp, full); err != nil {
						failed++
						continue
					}
					restored++
				}
				// ② 再恢复条目列表（产生新 rev，受管端据此重新取文件）
				rev := desired.Set(p.HWID, p.Items)
				log.Printf("[Desired] 临时临时授权到点：写回 %d 个文件、移除 %d 个（失败 %d）、恢复期望态 rev=%d（%d 项）%s",
					restored, removed, failed, rev, len(p.Items), p.Label)
				if failed > 0 {
					log.Printf("[Desired]  %d 个文件写回失败 —— 这次临时授权没有完全恢复，需要手工检查", failed)
				}
			}
		}
	}()
	// server 侧插件宿主（P3 第一步）：拉起 side=server 的插件并握手。
	// 放在这里而不是更上面：filestoreDir 是在这附近才定义出来的，
	// 在那之前引用它会编不过（我第一次挪错位置就是这么失败的）。
	pluginHost = NewPluginHost(filepath.Join(filestoreDir, "plugins"), stateDir)
	// 改成**同步**启动：路由是从 plugin.json 读出来的，必须在开始服务之前
	// 注册好，否则插件声明接管的路径会 404。
	// 代价：某个插件握手卡住会让启动最多多等 5 秒（握手超时）—— 可接受，
	// 而"插件起来了但它的路由没生效"是不可接受的（那会表现为神秘 404）。
	pluginHost.Start()
	// 把工件台账的校验函数集成宿主：artifact 鉴权路由（R6MLock 那几条）靠它判别。
	pluginHost.RegisterRoutes(mux, sessions, agents, artifacts.AuthByKey)

	// 放在这里是因为 desired / agents / filestoreDir 在这一带都已就绪。
	registerPolicyRoutes(mux, sessions, filestoreDir, desired, agents)

	// ── 手机控制台（2026-10-10）──
	mux.HandleFunc("/m/whoami", handleWhoami)
	mux.HandleFunc("/m", func(w http.ResponseWriter, r *http.Request) {
		handleMobile(w, r, filestoreDir)
	})

	// server 侧插件的调用入口（/api/plugin/call、/api/plugins/audit）
	registerPluginRoutes(mux, sessions, pluginHost)

	// ═══ 插件元数据（面板用，会话鉴权）═══
	// 与 /api/plugins 分开：那个是给受管端同步文件用的（agent 鉴权 + 文件清单），
	// 面板要的是"这是什么插件、需要什么文件、界面该长什么样"。
	// 两类消费者混在一个端点里，以后必然为其中一方改坏另一方。
	mux.HandleFunc("/api/plugins/meta", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		pluginDir := filepath.Join(filestoreDir, "plugins")
		entries, err := os.ReadDir(pluginDir)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": true, "plugins": []interface{}{}})
			return
		}
		var out []map[string]interface{}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(pluginDir, e.Name(), "plugin.json"))
			if err != nil {
				continue
			}
			// 直接透传原始字段 + 把声明里的 requires/ui 一并带上。
			// 用通用 map 而不是固定结构体：插件以后加字段不必改服务端。
			var meta map[string]interface{}
			if json.Unmarshal(raw, &meta) != nil {
				continue
			}
			if _, ok := meta["id"]; !ok {
				meta["id"] = e.Name()
			}
			// 统计它有多少个后端工具（有 .py 才算"带工具的能力包"）
			hasTools := false
			if fs, err := os.ReadDir(filepath.Join(pluginDir, e.Name())); err == nil {
				for _, f := range fs {
					if strings.HasSuffix(f.Name(), ".py") {
						hasTools = true
						break
					}
				}
			}
			meta["has_tools"] = hasTools
			// 运行状态：这个插件**在服务端到底跑没跑起来**。
			// 不做「装了的插件看着都在、其实一个都没起」这种事 ——
			// 本项目反复吃过静默失败的亏，所以这里必须把 state/err/tools 一起给出去。
			if st, ok := pluginHost.States()[e.Name()]; ok {
				meta["run"] = st
			}
			out = append(out, meta)
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "plugins": out})
	})

	// ═══ Runtime Sync ═══
	// Agent pulls embedded runtime (Python/Node) — agent auth required
	mux.HandleFunc("/api/runtime", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get(hdrAgentHWID), agents) {
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
		if !checkAgentAuth(r, r.Header.Get(hdrAgentHWID), agents) {
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
		if !checkAgentAuth(r, r.Header.Get(hdrAgentHWID), agents) {
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

			// 下发该插件的完整文件清单。
			// 客户端原来靠"从 command 字段里猜 .py 文件名"来决定下哪些文件，
			// 一旦 command 写法不同（python3 x.py、带参数、多文件）就会漏下，
			// 实测表现为"同步成功但工具数为 0"。由服务端明确列出文件才是可靠做法。
			var files []string
			// 每个文件的 sha256 —— 客户端据此判"内容变了没有"。
			//
			// **服务端改了插件，受管端永远不拉新版**（文件"存在"就直接跳过），
			// 重启也不拉。那正是"投放看起来不自动"的真身：首次自动、之后永不更新。
			// 保留 files[]（字符串数组）原样下发，老客户端不受影响。
			fileHashes := map[string]string{}
			if dirEntries, derr := os.ReadDir(filepath.Join(pluginDir, e.Name())); derr == nil {
				for _, de := range dirEntries {
					if de.IsDir() {
						continue
					}
					files = append(files, de.Name())
					if raw, rerr := os.ReadFile(filepath.Join(pluginDir, e.Name(), de.Name())); rerr == nil {
						sum := sha256.Sum256(raw)
						fileHashes[de.Name()] = hex.EncodeToString(sum[:])
					}
				}
			}

			plugins = append(plugins, map[string]interface{}{
				"id":          e.Name(),
				"name":        meta.Name,
				"version":     meta.Version,
				"command":     meta.Command,
				"description": meta.Description,
				"files":       files,
				"file_hashes": fileHashes,
			})
		}
		writeJSON(w, 200, plugins)
	})

	// Agent pulls a file from plugin directory (agent auth required)
	mux.HandleFunc("/api/plugins/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get(hdrAgentHWID), agents) {
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
			// 这两个字段**必须显式声明**：下面 json.Marshal(body) 是把结构体重新
			// 序列化成命令参数，少一个字段就等于把它吃掉 ——
			// 客户端那侧早就支持 artifact，却因为这里没有它而永远收不到
			// （投放链路一直"推下去了但没签发密钥"就是这个原因）。
			Artifact bool `json:"artifact"` // true=按外置工件处理：签发密钥+写配置+登记
			Run      bool `json:"run"`      // true=投放后启动它（在签发密钥之后）
			// RunMode 指定"以什么身份运行"（2026-10-11 第 2 步）
			//   ""/"user" = 当前身份（旧行为，默认）· "admin" = 以管理员拉起（runas）
			// 必须显式声明：下面 json.Marshal(body) 按本结构体重新序列化，少字段等于吃掉它
			RunMode string `json:"run_mode"`
			// 工件"落地之后怎么应用"：none/exe/zip/reg/policy/ps1/bat/msi/
			// cert/task/service/hosts/firewall/secedit。默认 none（仅落地）。
			// 同样必须显式声明 —— 下面 json.Marshal(body) 会按这个结构体重新序列化，
			// 少一个字段就等于把它吃掉（上次 artifact 就是这么被吞的）。
			Apply     string `json:"apply"`
			ApplyArgs string `json:"apply_args"`
			DryRun    bool   `json:"dry_run"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if !agents.HasKey(body.AgentHWID) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		cmdData, _ := json.Marshal(body)
		// 不给 id，管理端就只能猜"到底成没成"。有了它可以用
		// GET /api/mcp/result?request_id= 取回受管端报的真实结果/错误。
		reqID, err := cmds.Enqueue(body.AgentHWID, "deploy_file", string(cmdData))
		if err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "status": "dispatched", "request_id": reqID})
	})

	// ═══ 声明期望态 ═══
	// 管理端读/写某台机的期望态（会话鉴权）
	mux.HandleFunc("/api/desired", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if r.Method == "GET" {
			if hwid == "" {
				writeJSON(w, 400, map[string]string{"error": "missing hwid"})
				return
			}
			s := desired.Get(hwid)
			if s == nil {
				writeJSON(w, 200, map[string]interface{}{"ok": true, "rev": 0, "items": []interface{}{}})
				return
			}
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "hwid": s.HWID, "rev": s.Rev, "items": s.Items,
				"updated_ms": s.UpdatedMs, "status": desired.Status(hwid)})
			return
		}
		limitJSONBody(w, r)
		var body struct {
			HWID  string        `json:"hwid"`
			Items []DesiredItem `json:"items"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.HWID == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid/items"})
			return
		}
		rev := desired.Set(body.HWID, body.Items)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "rev": rev,
			"items": len(body.Items), "note": "受管端下一轮 poll 会看到 rev 变化并自动收敛"})
	})

	// 收敛历史：每次改期望态的设定时间 / 达成时间 / 耗时 / 失败项（会话鉴权）
	mux.HandleFunc("/api/desired/history", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "hwid": hwid,
			"current_rev": desired.Rev(hwid),
			"history":     desired.History(hwid),
		})
	})

	// 受管端取全量期望态（受管端鉴权）
	mux.HandleFunc("/api/agent/desired", func(w http.ResponseWriter, r *http.Request) {
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			hwid = r.Header.Get(hdrAgentHWID)
		}
		if !checkAgentAuth(r, hwid, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		s := desired.Get(hwid)
		if s == nil {
			writeJSON(w, 200, map[string]interface{}{"ok": true, "rev": 0, "items": []interface{}{}})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "rev": s.Rev, "items": s.Items})
	})

	// 受管端上报运行事实（受管端鉴权）：admin / 端点 / 失败数 / 达成 rev
	mux.HandleFunc("/api/agent/status", func(w http.ResponseWriter, r *http.Request) {
		limitJSONBody(w, r)
		var st AgentStatus
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil || st.HWID == "" {
			writeJSON(w, 400, map[string]string{"error": "missing hwid"})
			return
		}
		if !checkAgentAuth(r, st.HWID, agents) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		desired.SetStatus(&st)
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	// 事务化批量投放：一次提交多个工件，**全成或全回滚**。
	// items 里每项与单件投放同构（file_name/target_dir/apply/apply_args/artifact/run）。
	// 为什么要事务：批量投策略最糟的状态是"投了一半失败"——机器半配置且不知道该信哪边。
	mux.HandleFunc("/api/files/deploy_batch", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		limitJSONBody(w, r)
		var body struct {
			AgentHWID string          `json:"agent_hwid"`
			Tx        string          `json:"tx"`
			Items     json.RawMessage `json:"items"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Items) == 0 {
			writeJSON(w, 400, map[string]string{"error": "missing items"})
			return
		}
		if !agents.HasKey(body.AgentHWID) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		if body.Tx == "" {
			body.Tx = fmt.Sprintf("tx-%d", time.Now().UnixNano())
		}
		cmdData, _ := json.Marshal(body)
		reqID, err := cmds.Enqueue(body.AgentHWID, "deploy_batch", string(cmdData))
		if err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "status": "dispatched", "tx": body.Tx, "request_id": reqID})
	})

	// 按事务回滚整批
	mux.HandleFunc("/api/files/rollback_tx", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			AgentHWID string `json:"agent_hwid"`
			Tx        string `json:"tx"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Tx == "" || !agents.HasKey(body.AgentHWID) {
			writeJSON(w, 400, map[string]string{"error": "missing tx or unknown hwid"})
			return
		}
		cmdData, _ := json.Marshal(body)
		reqID, err := cmds.Enqueue(body.AgentHWID, "rollback_tx", string(cmdData))
		if err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "status": "dispatched", "request_id": reqID})
	})

	// 工件回滚：从最近一次备份还原（注册表/策略/hosts/防火墙/证书/任务/服务…）
	mux.HandleFunc("/api/files/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			AgentHWID string `json:"agent_hwid"`
			FileName  string `json:"file_name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if !agents.HasKey(body.AgentHWID) {
			writeJSON(w, 404, map[string]string{"error": "unknown agent hwid"})
			return
		}
		cmdData, _ := json.Marshal(body)
		reqID, err := cmds.Enqueue(body.AgentHWID, "rollback_file", string(cmdData))
		if err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "status": "dispatched", "request_id": reqID})
	})

	// Download file (agent pulls this — agent auth required)
	mux.HandleFunc("/api/files/get", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, r.Header.Get(hdrAgentHWID), agents) {
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
	// 证书与 filestore 同级生成并自启动配置，标识稳定供客户端 pinning
	exePath, _ := os.Executable()
	certDir := filepath.Dir(exePath)
	certFile, keyFile, fingerprint, err := ensureCert(certDir)
	if err != nil {
		log.Fatalf("[TLS] 证书初始化失败: %v", err)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: spoofMiddleware(mux),
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
	log.Printf("[TLS] 证书 SHA-256 标识: %s", fingerprint)
	log.Printf("[TLS] 将此标识填入客户端 PINNED_CERT_SHA256 常量（StubCore.cpp）")
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
// 优先级：环境变量 RMM_AGENT_KEY > 可执行文件同级 agent.key 文件 > 新随机生成。
// 密钥自启动配置保证重启后不变，否则所有 agent 失联。
func loadOrCreateAgentKey() string {
	if v := os.Getenv("RMM_AGENT_KEY"); v != "" {
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
	got := r.Header.Get(hdrAgentKey)
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
	got := r.Header.Get(hdrAgentKey)
	return subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1
}

// limitJSONBody 限制 JSON 请求体大小，防内存 DoS
func limitJSONBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
}

// 结果体上限：/api/agent/result 专用，**不能**沿用 limitJSONBody 的 1 MB。
//
// 为什么（实测 2026-10-07）：截图工具返回的是 BMP base64，实测 scale=2 的
// 后果不止"这一条结果丢了"：MaxBytesReader 在 1 MB 处**停止读取**，而客户端
// 出去，面板看起来是"整台机器卡死"。
// 上限取 48 MB：插件侧自限 32 MB base64（screen_capture.py 的 MAX_B64_CHARS），
// 留出 JSON 转义与包装余量。可用 RMM_MAX_RESULT_BYTES 覆盖。
var resultBodyLimit = func() int64 {
	if v := strings.TrimSpace(os.Getenv("RMM_MAX_RESULT_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
		log.Printf("[Server] RMM_MAX_RESULT_BYTES 值非法(%q)，改用默认值", v)
	}
	return 48 << 20
}()

func limitResultBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, resultBodyLimit)
}

// limitJSONBodyFrame 屏幕帧专用上限。
// 单独写一个而不是复用 limitJSONBody：那个是 1MB，用在帧接口上会重现
func limitJSONBodyFrame(w http.ResponseWriter, r *http.Request, limit int64) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

// ── 权限校验的一次性码（TOTP / RFC 6238）───────────────────────────────────────
// 三处必须算得一模一样：VM 内 gate.ps1、主机 r6m_totp.py、这里。
// 参数：HMAC-SHA1 / 30 秒一步 / 动态截断 / 取模 1000000 / 补零到 6 位。
const gateSecretPath = "/mnt/mmc0-4/r6m-server/gate.secret"

func gateTotp(secretHex string, step int64) (string, bool) {
	key, err := hex.DecodeString(strings.TrimSpace(secretHex))
	if err != nil || len(key) == 0 {
		return "", false
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000), true
}

// key=secret / msg="pw|"+window / HMAC-SHA256 / 取前 8 字节大端 uint64 / %10^16 / 左补零到 16 位
func gatePwd(secretHex string, win int64) (string, bool) {
	key, err := hex.DecodeString(strings.TrimSpace(secretHex))
	if err != nil || len(key) == 0 {
		return "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pw|" + strconv.FormatInt(win, 10)))
	sum := mac.Sum(nil)
	v := binary.BigEndian.Uint64(sum[:8])
	return fmt.Sprintf("%08d", v%100000000), true
}

// ═══════════════════════════════════════════════════════════════════════════
// 手机控制台（2026-10-10）
// ═══════════════════════════════════════════════════════════════════════════

const mobileAllowFile = "mobile_allowlist.json"

func mobileAllowPatterns(filestoreDir string) []string {
	b, err := os.ReadFile(filepath.Join(filestoreDir, mobileAllowFile))
	if err != nil {
		return nil
	}
	var v struct {
		Patterns []string `json:"patterns"`
		Note     string   `json:"note"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	out := []string{}
	for _, p := range v.Patterns {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func mobileUAAllowed(ua string, pats []string) bool {
	if len(pats) == 0 {
		return true // 名单空 = 未启用限制 
	}
	l := strings.ToLower(ua)
	for _, p := range pats {
		if strings.Contains(l, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// /m/whoami —— 把 UA 原样吐出来（含 JSON 形态，便于直接抄进白名单）
func handleWhoami(w http.ResponseWriter, r *http.Request) {
	ua := r.UserAgent()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;background:#111;color:#eee;padding:16px;line-height:1.6}
code{background:#222;padding:8px;display:block;word-break:break-all;border-radius:6px;font-size:13px}</style>
<h3>你的 User-Agent</h3><code>%s</code>
<p>把上面这一整串（或其中稳定的片段，例如 <b>OPPO</b> 与型号代号）发给我，我把它写进白名单即完成锁定。</p>
<p>若要临时自检：白名单文件在服务端 <code>filestore/mobile_allowlist.json</code></p>
<p><a style="color:#6cf" href="/m">去手机控制台 </a></p>`, htmlEscape(ua))
}

// /m —— 手机控制台（单文件）
func handleMobile(w http.ResponseWriter, r *http.Request, filestoreDir string) {
	ua := r.UserAgent()
	pats := mobileAllowPatterns(filestoreDir)
	if !mobileUAAllowed(ua, pats) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(403)
		fmt.Fprintf(w, `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;background:#111;color:#eee;padding:16px;line-height:1.6}
code{background:#222;padding:8px;display:block;word-break:break-all;border-radius:6px;font-size:13px}</style>
<h3>⛔ 这台设备不在白名单里</h3>
<p>当前 UA：</p><code>%s</code>
<p>要临时授权，请把下面这段写进服务端 <code>filestore/mobile_allowlist.json</code>：</p>
<code>{"patterns":["%s"],"note":"允许的设备"}</code>
<p>（也可以在浏览器直接打开 <a style="color:#6cf" href="/m/whoami">/m/whoami</a> 看 UA 全文）</p>`, htmlEscape(ua), htmlEscape(mobileGuessKey(ua)))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(mobileConsoleHTML))
}

// 从 UA 里猜一个"够用但不必精确"的匹配片段：优先 OPPO/品牌词 + 括号里的型号代号
func mobileGuessKey(ua string) string {
	for _, k := range []string{"OPPO", "oppo", "OnePlus", "vivo", "Xiaomi", "HUAWEI", "HONOR", "realme"} {
		if strings.Contains(ua, k) {
			return k
		}
	}
	// 括号里倒数第二段常是型号代号（如 Android 14; PJD110 Build/...）
	if m := regexp.MustCompile(`Android[^;]*;\s*([A-Za-z0-9_\- ]+)\s+Build/`).FindStringSubmatch(ua); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ua
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

const mobileConsoleHTML = `<!doctype html>
<html lang=zh><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>R6M 手机控制台</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--fg:#e8eaed;--mut:#9aa0a6;--acc:#4f8cff;--ok:#2ecc71;--warn:#f39c12;--bad:#e74c3c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"PingFang SC",sans-serif;padding:12px 12px 40px}
h1{font-size:18px;margin:6px 0 12px}
.card{background:var(--card);border-radius:12px;padding:12px;margin:10px 0}
label{display:block;color:var(--mut);font-size:13px;margin:8px 0 4px}
input,select{width:100%;padding:11px;border-radius:9px;border:1px solid #2a2f3a;background:#0d1016;color:var(--fg);font-size:16px}
button{padding:12px 14px;border-radius:10px;border:0;background:var(--acc);color:#fff;font-size:15px;margin:6px 6px 0 0}
button.g{background:#2a3140}
button.d{background:#5a2a2a}
.row{display:flex;flex-wrap:wrap;gap:8px}
.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;background:#222834;color:var(--mut)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
pre{white-space:pre-wrap;word-break:break-all;font-size:12px;color:var(--mut);margin:6px 0 0}
#scr{width:100%;border-radius:10px;background:#000;display:block}
a{color:var(--acc)}
</style>
<h1>R6M 手机控制台</h1>

<div class=card id=loginCard>
  <label>服务器</label><input id=srv placeholder="https://192.168.1.10:8443">
  <label>账号</label><input id=usr value=admin autocomplete=username>
  <label>密码</label><input id=pwd type=password autocomplete=current-password>
  <div class=row><button onclick=doLogin()>登录</button></div>
  <pre id=loginMsg></pre>
</div>

<div class=card id=mainCard style="display:none">
  <div class=row style="justify-content:space-between;align-items:center">
    <span class=pill id=conn>未连接</span>
    <span><button class=g onclick=refresh()>刷新</button></span>
  </div>
  <label>受管端</label><select id=agent onchange=onAgent()></select>
  <pre id=agentInfo></pre>
</div>

<div class=card id=formsCard style="display:none">
  <label>形态（一键下发）</label>
  <div class=row>
    <button onclick=applyForm('form_locked')>🔒 一键锁死</button>
    <button onclick=applyForm('form_tempadmin')>🔓 临时开放管理员</button>
    <button onclick=applyForm('form_open')>🧹 解锁使用</button>
    <button onclick=applyForm('form_open_admin')>🔧 兼容模式</button>
  </div>
  <div class=row style="margin-top:8px">
    <button class=g onclick=applyAsset('desk_pw_on')>桌面密码·开</button>
    <button class=g onclick=applyAsset('desk_pw_off')>桌面密码·关</button>
    <button class=g onclick=applyAsset('admin_mode_off')>退出临时授权（权限回收）</button>
  </div>
  <pre id=formMsg></pre>
</div>

<div class=card id=scrCard style="display:none">
  <label>屏幕（实时）</label>
  <img id=scr alt=screen>
  <div class=row style="margin-top:8px">
    <button onclick=scrStart()>开始</button>
    <button class=g onclick=scrStop()>停止</button>
  </div>
  <pre id=scrMsg></pre>
</div>

<script>
let base='', hwid='', timer=null, seq=0;
const $=id=>document.getElementById(id);
function msg(el,s,cls){const e=$(el);e.textContent=s;e.className=cls||''}
function api(path,body){
  return fetch(base+path,{method:body?'POST':'GET',credentials:'include',
    headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined})
    .then(r=>r.text().then(t=>({ok:r.ok,status:r.status,text:t})));
}
function j(s){try{return JSON.parse(s)}catch(e){return null}}
async function doLogin(){
  base=$('srv').value.trim().replace(/\/$/,'');
  if(!base){msg('loginMsg','请填服务器地址','warn');return}
  localStorage.setItem('r6m_srv',base);
  msg('loginMsg','登录中…');
  const r=await api('/api/login',{user:$('usr').value,pass:$('pwd').value});
  const o=j(r.text);
  if(!o||o.ok!==true){msg('loginMsg','登录失败：'+(r.text||r.status),'bad');return}
  msg('loginMsg','登录成功 ','ok');
  $('loginCard').style.display='none';$('mainCard').style.display='';$('formsCard').style.display='';$('scrCard').style.display='';
  refresh();
}
async function refresh(){
  const a=await api('/api/agents'); const o=j(a.text); const list=(o&&(o.agents||o))||[];
  const sel=$('agent'); sel.innerHTML='';
  if(!list.length){msg('agentInfo','没有受管端','warn');return}
  list.forEach(x=>{const op=document.createElement('option');op.value=x.hwid;
    op.textContent=(x.hostname||x.hwid.slice(0,8))+' '+(x.online?'在线':'离线');sel.appendChild(op)});
  hwid=list[0].hwid; onAgent();
}
function onAgent(){
  hwid=$('agent').value;
  api('/api/agents').then(a=>{const o=j(a.text);const list=(o&&(o.agents||o))||[];
    const x=list.find(y=>y.hwid===hwid); if(!x)return;
    $('agentInfo').textContent='hwid='+x.hwid+'\n在线='+x.online+'  已应用 rev='+(x.applied_rev||'-')+'\n系统='+(x.os||'-')+'\n最后心跳='+(x.last_seen?new Date(x.last_seen).toLocaleString():'-');
    $('conn').textContent=x.online?'受管端在线':'受管端离线'; $('conn').className='pill '+(x.online?'ok':'bad');
  });
  api('/api/gate/code').then(g=>{const o=j(g.text); if(o&&o.ok) $('formMsg').textContent='当前提升权限码：'+(o.pwd||'-')+'（剩 '+(o.pwd_remaining||'-')+'s）用户名 '+(o.user||'r6mop')});
}
async function applyForm(p){
  if(!hwid){msg('formMsg','先选受管端','warn');return}
  msg('formMsg','下发 '+p+' …');
  const r=await api('/api/policies/apply',{hwid:hwid,pack:p}); const o=j(r.text);
  msg('formMsg',(o&&o.error)?('失败：'+o.error):('已下发 '+(o.pack_name||p)+' rev='+(o.rev||'?')),o&&o.error?'bad':'ok');
}
async function applyAsset(id){
  if(!hwid){msg('formMsg','先选受管端','warn');return}
  const r=await api('/api/policies/apply',{hwid:hwid,asset:id}); const o=j(r.text);
  msg('formMsg',(o&&o.error)?('失败：'+o.error):('资产 '+id+' 已下发 rev='+(o.rev||'?')),o&&o.error?'bad':'ok');
}
async function scrStart(){
  if(!hwid){msg('scrMsg','先选受管端','warn');return}
  await api('/api/screen/start',{hwid:hwid,scale:1,interval_ms:1000});
  msg('scrMsg','已请求开始（若黑屏  受管端在 session 0，是已知问题 ）');
  if(timer)clearInterval(timer); timer=setInterval(pull,1500); pull();
}
async function scrStop(){ if(timer){clearInterval(timer);timer=null} await api('/api/screen/stop',{hwid:hwid}); msg('scrMsg','已停止') }
async function pull(){
  const r=await api('/api/screen/latest?hwid='+hwid); const o=j(r.text);
  if(o&&o.image_base64){ $('scr').src='data:image/'+(o.format||'png')+';base64,'+o.image_base64;
    const kb=Math.round((o.image_base64.length*0.75)/1024);
    msg('scrMsg','第 '+(++seq)+' 帧  '+o.width+'x'+o.height+'  '+kb+'KB  '+(kb<8?'(偏小  可能全黑 )':'')); }
  else msg('scrMsg','暂无帧：'+(r.text||r.status));
}
(function init(){
  const s=localStorage.getItem('r6m_srv'); if(s)$('srv').value=s; else $('srv').value=location.origin;
  if(location.protocol!=='https:') msg('loginMsg','提示：若用 http 打开可能无法登录（服务端是 https ）','warn');
})();
</script>
</html>`

func checkAuth(r *http.Request, s *SessionManager) bool {
	for _, c := range r.Cookies() {
		if c.Name == cookieName && s.Validate(c.Value) {
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
		fmt.Println("用法: rmm-server agent list|info <hwid>")
		os.Exit(1)
	}
	base := getEnv("RMM_API", "https://127.0.0.1:8080")
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
		fmt.Println("用法: rmm-server mcp call <hwid> <tool> <json-args>")
		os.Exit(1)
	}
	if args[0] != "call" {
		fmt.Println("仅支持 call 子命令")
		os.Exit(1)
	}
	base := getEnv("RMM_API", "https://127.0.0.1:8080")
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
	user := getEnv("RMM_USER", "admin")
	pass := getEnv("RMM_PASS", "changeme")
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
		if c.Name == cookieName {
			return c.Value
		}
	}
	return ""
}

func getJSON(url, token string) []byte {
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Cookie", cookieName+"="+token)
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
		req.Header.Set("Cookie", cookieName+"="+token)
	}
	resp, err := cliClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return out
}


// ═══════════════════════════════════════════════════════════════════════════
// 兼容性适配：高识别度字面量改用混淆表（server/obf_strings_gen.go 生成）
//
// 为什么用变量而不是直接把明文写回调用点：
//   明文出现在源码里是必要的（可读性、可维护性），工具生成的密文表保证了
//   **编译进二进制的是密文**。obfSeed() 在 init 期算出与工具一致的种子，
//   再由 obf() 解密 —— 静态扫描拿不到明文。
//
// 失败模式：若清单里漏了某个字面量，obf() 会返回空串，而空串会让协议失效
// （所有人都能用任意值通过鉴权）。所以这里必须**显式校验**，宁可启动失败。
// ═══════════════════════════════════════════════════════════════════════════
var (
	hdrAgentKey  string
	hdrAgentHWID string
	cookieName   string
)

func init() {
	// 种子常量由 tools/gen_obf_strings.py 生成（名字带种子后缀，避免不同大小写
	// 的明文归一化成同名常量）。**只用数字常量**，不要在源码里写明文再运行期算
	// 种子 —— 那会把明文编进二进制（实测踩过）。
	hdrAgentKey = obf(ObfSeed_X_Agent_Key_4F478BB9)
	hdrAgentHWID = obf(ObfSeed_X_Agent_HWID_2162F176)
	cookieName = obf(ObfSeed_c2session_B16FDECC)

	for name, v := range map[string]string{
		"hdrAgentKey": hdrAgentKey, "hdrAgentHWID": hdrAgentHWID, "cookieName": cookieName,
	} {
		if v == "" {
			log.Fatalf("[obf] 混淆表缺失 %s —— 请重新运行 tools/gen_obf_strings.py 并检查 obf_manifest.txt", name)
		}
	}
}

// ── 会话自启动配置 ────────────────────────────────────────────────────────────
// 服务端重启（部署/崩溃/断电）不该让所有管理端重新登录 ——
// 实测的代价是：面板静默 401 洪水 + 界面一直显示旧数据，而人看不出是"登录掉了"。
func (s *SessionManager) sessionsPath() string {
	if s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, "sessions.json")
}

func (s *SessionManager) loadLocked() {
	p := s.sessionsPath()
	if p == "" {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var saved map[string]int64
	if json.Unmarshal(raw, &saved) != nil {
		log.Printf("[Session] %s 解析失败，按无会话启动", p)
		return
	}
	now := time.Now().UnixMilli()
	n := 0
	for tok, exp := range saved {
		if exp > now { // 过期的直接丢，不延长任何人的会话
			s.sessions[tok] = exp
			n++
		}
	}
	if n > 0 {
		log.Printf("[Session] 已恢复 %d 个未过期会话（重启不踢人）", n)
	}
}

// 落盘。用临时文件 + rename：写一半的会话表被读进来比"没写"更糟。
func (s *SessionManager) saveLocked() {
	p := s.sessionsPath()
	if p == "" {
		return
	}
	raw, err := json.Marshal(s.sessions)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, raw, 0600) != nil {
		return
	}
	if os.Rename(tmp, p) != nil {
		log.Printf("[Session] 会话表落盘失败: %s", p)
	}
}
