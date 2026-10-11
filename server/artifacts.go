package main

// ═══════════════════════════════════════════════════════════════════════════
// artifacts.go —— 外置工件的密钥登记表
//
// 解决什么问题：外置工具（如 R6MLock.exe）是**投放**下去的一次性件，
// 它不该携带受管端的 per-agent 密钥（工具配置一旦泄露就危及受管端本身）。
// 所以给每个工件单独签发一把 key，并在服务端登记 key ↔ 工件的对应关系：
// 管理端因此能回答"这把钥匙对应哪个文件、哪个进程"，重新投放时复用同一把 key，
// 服务端就能认出"还是同一个工件"，解锁/续期都对得上号。
//
// 为什么密钥由**受管端签发**（而不是服务端生成）：
//   受管端是唯一知道"文件实际落在哪、以什么进程跑起来"的一方；
//   由它生成 key 并连同这些事实一起上报，服务端只做登记与核对，
//   避免出现"服务端以为投放到了 A，实际落在 B"的错配。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 外置工件用它**自己的**密钥鉴权 —— 与受管端的 per-agent 密钥是两把不同的钥匙。
// 放在这里而不是 main.go 的常量块里：这个头部名是工件机制的内部约定，
// 跟着工件表走更不容易被误改。
const hdrArtifactKey = "X-Artifact-Key"

type Artifact struct {
	HWID       string `json:"hwid"`
	Name       string `json:"name"`   // 文件名，如 R6MLock.exe
	SHA256     string `json:"sha256"` // 文件标识，用于确认"还是同一个工件"
	Size       int64  `json:"size"`
	Path       string `json:"path"` // 落地绝对路径
	Proc       string `json:"proc"` // 进程名
	PID        int    `json:"pid"`
	Key        string `json:"key"` // 该工件专属密钥（由受管端签发）
	DeployedMs int64  `json:"deployed_ms"`
	SeenMs     int64  `json:"seen_ms"`
}

type artifactState struct {
	Version int                  `json:"version"`
	SavedAt int64                `json:"saved_at"`
	Items   map[string]*Artifact `json:"items"` // key -> artifact
}

type ArtifactHub struct {
	mu    sync.Mutex
	dir   string
	key   []byte
	items map[string]*Artifact
}

const artifactFormatVersion = 1

func NewArtifactHub(dir string, key []byte) *ArtifactHub {
	h := &ArtifactHub{dir: dir, key: key, items: make(map[string]*Artifact)}
	h.load()
	return h
}

func (h *ArtifactHub) path() string { return filepath.Join(h.dir, "artifacts.json") }

func (h *ArtifactHub) load() {
	blob, err := os.ReadFile(h.path())
	if err != nil {
		return
	}
	plain, err := openState(h.key, blob)
	if err != nil {
		bad := fmt.Sprintf("%s.bad-%d", h.path(), time.Now().Unix())
		_ = os.Rename(h.path(), bad)
		log.Printf("[Artifact] artifacts.json 解密失败（已另存 %s）: %v", filepath.Base(bad), err)
		return
	}
	var st artifactState
	if err := json.Unmarshal(plain, &st); err != nil {
		log.Printf("[Artifact] artifacts.json 解析失败: %v", err)
		return
	}
	for k, v := range st.Items {
		h.items[k] = v
	}
	log.Printf("[Artifact] 已恢复 %d 个工件登记", len(h.items))
}

func (h *ArtifactHub) saveLocked() {
	st := artifactState{Version: artifactFormatVersion, SavedAt: time.Now().UnixMilli(), Items: h.items}
	plain, err := json.Marshal(st)
	if err != nil {
		return
	}
	blob, err := sealState(h.key, plain)
	if err != nil {
		log.Printf("[Artifact] 加密失败: %v", err)
		return
	}
	tmp := h.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return
	}
	f.Sync()
	f.Close()
	if err := os.Rename(tmp, h.path()); err != nil {
		log.Printf("[Artifact] rename 失败: %v", err)
	}
}

// Register 登记一个工件，并**强制 key ↔ 工件 一对一**。
//
// 返回 (被顶替的旧记录, 错误)。错误非空表示拒绝登记（调用方应回 409），
// 且此时状态未被修改 —— 这是"不会把钥匙投反"的核心保障：
// 一把钥匙一旦绑定到某个 (文件名, sha256)，就永远不能改指派给别的工件。
func (h *ArtifactHub) Register(a *Artifact) (*Artifact, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().UnixMilli()

	// ① key 不许改嫁
	if old, ok := h.items[a.Key]; ok {
		if old.Name != a.Name ||
			(old.SHA256 != "" && a.SHA256 != "" && old.SHA256 != a.SHA256) {
			return nil, fmt.Errorf(
				"密钥 %s… 已绑定到 %s(sha %s)，拒绝改指派给 %s(sha %s)：请改用该工件原有的密钥，或先作废旧登记",
				shortKey(a.Key), old.Name, short12(old.SHA256), a.Name, short12(a.SHA256))
		}
		// 同一工件原样重投：保留 DeployedMs，便于区分"首次投放"与"续投"
		a.DeployedMs = old.DeployedMs
	}

	// ② 同一台机器上同名工件只保留一条活跃记录。
	//    换了 key 说明本地配置被删/重建过：主动作废旧记录并把旧 key 回给调用方，
	//    让管理端明确看到"这个文件换钥匙了"，而不是面对两条记录不知该信谁。
	var replaced *Artifact
	for k, v := range h.items {
		if k != a.Key && v.HWID == a.HWID && v.Name == a.Name {
			cp := *v
			replaced = &cp
			delete(h.items, k)
			log.Printf("[Artifact] %s 的密钥已更换：%s… -> %s…（旧的作废）",
				a.Name, shortKey(k), shortKey(a.Key))
		}
	}

	if a.DeployedMs == 0 {
		a.DeployedMs = now
	}
	a.SeenMs = now
	h.items[a.Key] = a
	h.saveLocked()
	log.Printf("[Artifact] 登记工件 key=%s… %s hwid=%s pid=%d sha=%s path=%s",
		shortKey(a.Key), a.Name, a.HWID, a.PID, short12(a.SHA256), a.Path)
	return replaced, nil
}

// Resolve 按 (hwid, 文件名) 查已有工件 —— 让密钥的权威来源是服务端而不是本地 ini。
// 这样即使本地 R6MLock.ini 被删掉，重新投放时也能拿回**同一个** key，
// 不会出现"同一个文件两条 key 记录"的错配。
func (h *ArtifactHub) Resolve(hwid, name string) (*Artifact, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.items {
		if a.HWID == hwid && a.Name == name {
			cp := *a
			return &cp, true
		}
	}
	return nil, false
}

// Identity 回带工件身份（给 /api/lock/state 用）：工具据此能确认"我是哪个工件"，
// 而不只是"我有一把能通过的钥匙"。
func (h *ArtifactHub) Identity(key string) (string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.items[key]
	if !ok {
		return "", "", false
	}
	return a.Name, short12(a.SHA256), true
}

// short12 安全截断（原实现直接 [:8]，sha 为空串时会 panic）
func short12(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func shortKey(k string) string {
	if len(k) <= 8 {
		return k
	}
	return k[:8]
}

// AuthByKey 用工件密钥鉴权：key 必须存在且属于该 hwid。
func (h *ArtifactHub) AuthByKey(key, hwid string) bool {
	if key == "" || hwid == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.items[key]
	if !ok {
		return false
	}
	if a.HWID != hwid {
		return false
	}
	a.SeenMs = time.Now().UnixMilli()
	return true
}

func (h *ArtifactHub) List(hwid string) []*Artifact {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*Artifact
	for _, a := range h.items {
		if hwid == "" || a.HWID == hwid {
			cp := *a
			// 密钥不回传给面板列表：列表只需要"哪把钥匙对应哪个工件"，
			// 具体密钥值由管理端在需要投放时从注册响应里取，缩小暴露面。
			cp.Key = shortKey(a.Key) + "…"
			out = append(out, &cp)
		}
	}
	return out
}
