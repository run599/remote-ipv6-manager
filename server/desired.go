package main

// ═══════════════════════════════════════════════════════════════════════════
// desired.go —— 声明期望态（desired state）与受管端状态上报
//
// 为什么要它：原来的控制模型是"逐条发指令"。这有三个天然缺陷：
//   · agent 离线时指令根本没送到，然后被遗忘；
//   · 服务端重启（指令队列在内存里）在途指令就丢了；
//   · 100 台机器就是 100 条命令，且没有"最终是否达成"的概念。
//
// 就来取全量、按本地 ledger 对账、缺什么补什么，然后回报达成的 rev。
// 于是：离线机器回来自动收敛；投放到 100 台 = 改一次期望态；服务端重启不影响。
//
// 注意：这不是"更强的控制"，恰恰相反 —— 它靠的是**持久目标**而不是**更强的施压**。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

type DesiredItem struct {
	FileName  string `json:"file_name"`
	TargetDir string `json:"target_dir,omitempty"`
	Apply     string `json:"apply,omitempty"`
	ApplyArgs string `json:"apply_args,omitempty"`
	Artifact  bool   `json:"artifact,omitempty"`
	Run       bool   `json:"run,omitempty"`
	SHA256    string `json:"sha256,omitempty"` // 版本判据：不一致就换
	// From 标记这条期望态的**来源**（如 "plugin:task_lock" 或 "manual"）。
	// 为什么需要：插件"一键装"会把 requires 并进期望态；将来要卸载插件时，
	// 必须能按来源找出"哪些条目是这个插件带来的"，否则只能猜或全清。
	// 收敛逻辑不解释它，只原样保存与回报。
	From      string `json:"from,omitempty"`
	// RunID: 本次 apply 的唯一号。客户端据此判断"同一份内容是否要求再执行一次"
	// （资产的默认语义是"文件内容对就够"，那对命令式动作是错的 ⇒ 见 ConvergeDesired）
	RunID string `json:"run_id,omitempty"`
}

type DesiredSet struct {
	HWID      string        `json:"hwid"`
	Rev       int64         `json:"rev"`
	Items     []DesiredItem `json:"items"`
	UpdatedMs int64         `json:"updated_ms"`
}

// FileSnap 是一个文件在某个时刻的内容快照。
// Existed=false 表示"当时它还不存在" —— 恢复时应当把它删掉（那是我们自己创建的产物）。
type FileSnap struct {
	Name    string `json:"name"`
	Existed bool   `json:"existed"`
	Bytes   []byte `json:"bytes,omitempty"`
}

// PendingRevert 是一次"到点自动恢复"的预约。
//
// 解决什么问题：约束类策略（禁用注册表编辑器/命令提示符/限制安装…）会把**自己也**一起锁住，
// 于是把恢复做成预约：到点由服务端自己把期望态恢复成**应用前的快照**。
//
// 为什么快照而不是硬编码"限制那份值"：这样它对**任何**下发都通用
//（临时调一个注册表值、临时禁一个服务…都行），不必为每种场景各写一套。
type PendingRevert struct {
	HWID  string        `json:"hwid"`
	AtMs  int64         `json:"at_ms"`           // 到点时间（unix ms）
	Label string        `json:"label,omitempty"` // 人话：这次临时授权是为什么
	Items []DesiredItem `json:"items"`
	// Files 是"我们即将覆盖的那些文件"在覆盖**之前**的字节。
	// 必须连字节一起存：期望态条目只是一个**文件引用**，光恢复条目，文件内容还是
	Files []FileSnap `json:"files,omitempty"`           // 到点要恢复成的条目
}

// 为什么要它：只看到当前 rev 的即时状态，回答不了"上次那批到底多久才铺完、
// 有没有哪台一直没达成"。运维真正要的是这个时间线。
type ConvergeRecord struct {
	HWID       string   `json:"hwid"`
	Rev        int64    `json:"rev"`
	Items      int      `json:"items"`
	SetMs      int64    `json:"set_ms"`
	AchievedMs int64    `json:"achieved_ms"`          // 0 = 还没达成
	DurationMs int64    `json:"duration_ms"`          // 达成耗时（未达成为 0）
	Failed     []string `json:"failed,omitempty"`     // 最近一次上报的失败项
	FailedMs   int64    `json:"failed_ms,omitempty"`
	// SupersededMs / SupersededBy：这一版**既没达成也没失败**，而是被更新的 rev 取代了。
	// 它们看起来和"失败"一样（achieved_ms=0、failed 为空），于是时间线被噪声淹没，
	// 人分不清"真出错了"还是"我刚连点了几下保存"。
	SupersededMs int64 `json:"superseded_ms,omitempty"`
	SupersededBy int64 `json:"superseded_by,omitempty"`
	// Result 是给人看的四态：achieved / failed / superseded / in_progress。
	// 由服务端算好写进来，这样任何"直接打印原始 JSON"的界面也一眼能懂。
	Result string `json:"result"`
}

// 每台机最多留这么多条历史：历史不能无限涨（否则 desired.json 会一直变大）
const convergeHistoryMax = 50

// AgentStatus 是受管端主动上报的运行事实。
// "为什么这条指令没生效" —— 这个项目里"静默降级"已经坑过好几次。
type AgentStatus struct {
	HWID          string `json:"hwid"`
	Admin         bool   `json:"admin"`
	Endpoint      string `json:"endpoint"`
	EndpointIndex int    `json:"endpoint_index"`
	EndpointTotal int    `json:"endpoint_total"`
	EndpointFails int    `json:"endpoint_fails"`
	DesiredRev    string   `json:"desired_rev"`
	DesiredFailed []string `json:"desired_failed,omitempty"` // 上次收敛的失败项
	// DesiredDrift 自愈检查发现的"配置偏离"详情。
	// 客户端**早就在发**这个字段（形如 "r6m-policy.reg: 有 1 个注册表值不符，例如
	// 接上它之后，面板才能告诉操作者"**具体哪一项被改了**"，
	// 而不是只有一句"这个策略包有偏离"。
	DesiredDrift []string `json:"desired_drift,omitempty"`
	SeenMs        int64    `json:"seen_ms"`
}

type desiredState struct {
	Version  int                         `json:"version"`
	SavedAt  int64                       `json:"saved_at"`
	Sets     map[string]*DesiredSet      `json:"sets"`
	Statuses map[string]*AgentStatus     `json:"statuses"`
	History  map[string][]*ConvergeRecord `json:"history"`
	// Pending 是"到点自动恢复"的预约（临时临时授权用），必须自启动配置：
	// 否则服务端一重启，临时授权就永久生效了 —— 那比"忘了关回去"更糟。
	Pending  map[string]*PendingRevert    `json:"pending,omitempty"`
}

type DesiredHub struct {
	mu       sync.Mutex
	dir      string
	key      []byte
	sets     map[string]*DesiredSet
	statuses map[string]*AgentStatus
	history  map[string][]*ConvergeRecord
	pending map[string]*PendingRevert
}

func NewDesiredHub(dir string, key []byte) *DesiredHub {
	h := &DesiredHub{dir: dir, key: key,
		sets: make(map[string]*DesiredSet), statuses: make(map[string]*AgentStatus),
		history: make(map[string][]*ConvergeRecord)}
	h.load()
	return h
}

func (h *DesiredHub) path() string { return filepath.Join(h.dir, "desired.json") }

func (h *DesiredHub) load() {
	blob, err := os.ReadFile(h.path())
	if err != nil {
		return
	}
	plain, err := openState(h.key, blob)
	if err != nil {
		bad := h.path() + ".bad-" + time.Now().Format("20060102-150405")
		_ = os.Rename(h.path(), bad)
		log.Printf("[Desired] desired.json 解密失败（已另存 %s）: %v", filepath.Base(bad), err)
		return
	}
	var st desiredState
	if json.Unmarshal(plain, &st) != nil {
		return
	}
	if st.Sets != nil {
		h.sets = st.Sets
	}
	if st.Statuses != nil {
		h.statuses = st.Statuses
	}
	if st.History != nil {
		h.history = st.History
	if st.Pending != nil {
		h.pending = st.Pending
	} else {
		h.pending = map[string]*PendingRevert{}
	}
	}
	log.Printf("[Desired] 已恢复 %d 份期望态、%d 条状态上报", len(h.sets), len(h.statuses))
}

func (h *DesiredHub) saveLocked() {
	plain, err := json.Marshal(desiredState{
		Version: 1, SavedAt: time.Now().UnixMilli(),
		Sets: h.sets, Statuses: h.statuses, History: h.history})
	if err != nil {
		return
	}
	blob, err := sealState(h.key, plain)
	if err != nil {
		return
	}
	tmp := h.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	_, _ = f.Write(blob)
	_ = f.Sync()
	_ = f.Close()
	if err := os.Rename(tmp, h.path()); err != nil {
		log.Printf("[Desired] rename 失败: %v", err)
	}
}

// Set 覆盖某台机的期望态并**递增 rev**。rev 一变，受管端下一轮就会来收敛。

// sameItems 判断两批期望态条目"语义上完全一样"。
func sameItems(a, b []DesiredItem) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(it DesiredItem) string {
		return it.FileName + "\x1f" + it.TargetDir + "\x1f" + it.Apply + "\x1f" +
			it.ApplyArgs + "\x1f" + it.SHA256 + "\x1f" + it.From + "\x1f" +
			strconv.FormatBool(it.Artifact) + "\x1f" + strconv.FormatBool(it.Run) + "\x1f" + it.RunID
	}
	ka := make([]string, 0, len(a))
	kb := make([]string, 0, len(b))
	for _, it := range a {
		ka = append(ka, key(it))
	}
	for _, it := range b {
		kb = append(kb, key(it))
	}
	sort.Strings(ka)
	sort.Strings(kb)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func (h *DesiredHub) Set(hwid string, items []DesiredItem) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.sets[hwid]
	// 为什么：原来每次保存都 +1，于是"连点几下保存"就会造出一堆
	// 把真正的时间线（多久铺完、哪一版失败）淹没了。
	if cur != nil && sameItems(cur.Items, items) {
		return cur.Rev
	}
	var rev int64 = 1
	if cur != nil {
		rev = cur.Rev + 1
	}
	now := time.Now().UnixMilli()
	// 被这一版取代、且既没达成也没失败的历史记录 —— 标注清楚（三态分明）
	for _, old := range h.history[hwid] {
		if old.AchievedMs == 0 && old.FailedMs == 0 && old.SupersededMs == 0 {
			old.SupersededMs = now
			old.SupersededBy = rev
			old.Result = "superseded"
		}
	}
	h.sets[hwid] = &DesiredSet{HWID: hwid, Rev: rev, Items: items,
		UpdatedMs: now}
	// 记一条历史：这一刻的目标是什么、什么时候设的
	rec := &ConvergeRecord{HWID: hwid, Rev: rev, Items: len(items),
		SetMs: now, Result: "in_progress"}
	h.history[hwid] = append(h.history[hwid], rec)
	if n := len(h.history[hwid]); n > convergeHistoryMax {
		h.history[hwid] = h.history[hwid][n-convergeHistoryMax:]
	}
	h.saveLocked()
	log.Printf("[Desired] 设置 %s 的期望态 rev=%d，%d 项", hwid, rev, len(items))
	return rev
}

func (h *DesiredHub) Get(hwid string) *DesiredSet {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sets[hwid]
}

func (h *DesiredHub) Rev(hwid string) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.sets[hwid]; s != nil {
		return s.Rev
	}
	return 0
}

func (h *DesiredHub) SetStatus(s *AgentStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s.SeenMs = time.Now().UnixMilli()
	h.statuses[s.HWID] = s

	// 受管端上报的 desired_rev 是"**全部成功**才推进"的本地版本
	// （客户端逻辑：failed==0 才把 _desiredRev 设成新 rev），
	// 所以它等于某个历史 rev 就说明那一版**已经达成** —— 补上达成时间。
	hist := h.history[s.HWID]
	if s.DesiredRev != "" {
		if appliedRev, err := strconv.ParseInt(s.DesiredRev, 10, 64); err == nil {
			for i := len(hist) - 1; i >= 0; i-- {
				if hist[i].Rev == appliedRev {
					if hist[i].AchievedMs == 0 {
				hist[i].Result = "achieved"
						hist[i].AchievedMs = s.SeenMs
						hist[i].DurationMs = s.SeenMs - hist[i].SetMs
						log.Printf("[Desired] %s 达成 rev=%d，耗时 %dms",
							s.HWID, appliedRev, hist[i].DurationMs)
					}
					break
				}
			}
		}
	}
	// 失败项也记进当前那条未达成的历史 —— 这样历史里能直接看到"卡在哪一件"
	if len(s.DesiredFailed) > 0 && len(hist) > 0 {
		last := hist[len(hist)-1]
		if last.AchievedMs == 0 {
			last.Failed = s.DesiredFailed
			last.FailedMs = s.SeenMs
			last.Result = "failed"
		}
	}
	h.saveLocked()
}

// History 返回某台机的收敛历史（**新的在前**）
func (h *DesiredHub) History(hwid string) []*ConvergeRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	src := h.history[hwid]
	out := make([]*ConvergeRecord, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		cp := *src[i]
		out = append(out, &cp)
	}
	return out
}

func (h *DesiredHub) Status(hwid string) *AgentStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.statuses[hwid]
}

// ── 临时临时授权的预约（到点恢复）────────────────────────────────────────────

// AddPending 记下"到点把该机的期望态恢复成 items"。
func (h *DesiredHub) AddPending(hwid string, atMs int64, label string, items []DesiredItem, files []FileSnap) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil {
		h.pending = map[string]*PendingRevert{}
	}
	h.pending[hwid] = &PendingRevert{HWID: hwid, AtMs: atMs, Label: label, Items: items, Files: files}
	h.saveLocked()
}

// PendingFor 返回该机当前的预约（没有则 nil）。返回副本，调用方不必加锁。
func (h *DesiredHub) PendingFor(hwid string) *PendingRevert {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pending[hwid]
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// ClearPending 取消预约（比如操作者手动"立即恢复"）。
func (h *DesiredHub) ClearPending(hwid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.pending[hwid]; !ok {
		return false
	}
	delete(h.pending, hwid)
	h.saveLocked()
	return true
}

// DuePendings 取出所有已到点的预约**并从表里删掉**（调用方负责按 Items 恢复）。
// 先删后做：万一恢复过程出错，也不会每 5 秒重试一次刷同一件事。
func (h *DesiredHub) DuePendings(nowMs int64) []*PendingRevert {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*PendingRevert
	for k, p := range h.pending {
		if p.AtMs <= nowMs {
			cp := *p
			out = append(out, &cp)
			delete(h.pending, k)
		}
	}
	if len(out) > 0 {
		h.saveLocked()
	}
	return out
}
