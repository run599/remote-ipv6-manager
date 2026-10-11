package main

// ═══════════════════════════════════════════════════════════════════════════
// screen.go —— 屏幕监控（实时看屏）的服务端部分
//
// 为什么需要"会话 + 最新帧信箱"这一层，而不是让面板反复调截图工具：
//   照这条路做"连续截图"，一帧最快也要 3~4 秒 —— 那是幻灯片，不是监控。
//
//   所以拆成三层各自独立跑：
//     面板   ──POST /api/screen/start{scale,interval_ms}──▶ 服务端建会话
//     面板   ──GET /api/screen/latest（按自己的显示节奏）──▶ 取最新一帧
//   采集速率、上行速率、显示速率互不阻塞。服务端**只保留最新一帧**，
//   积压天然被覆盖丢弃 —— 监控要的是"现在"，不是"三秒前排队的那一帧"。
//
// 帧以 base64 字符串原样透传（不 decode 再 encode）：
//   服务端是 RK3568 这种小机器，每帧 36KB，10fps 下反复编解码是白烧 CPU；
//   原样存原样发，一次拷贝都不做。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"log"
	"sync"
	"time"
)

const (
	// 单帧上限：PNG 在 scale=4 下约 36KB、scale=1 下也就几百 KB。
	// 给 8MB 是留足余量同时挡住畸形/恶意大包（这个接口带 agent 密钥，但仍不值得信任）。
	screenMaxFrameBytes = 8 << 20
	// 会话静默上限：超过这个时间没有新帧就视为已死（面板关了没点停止、
	// 受管端退出、网络断），自动清理，避免受管端在无人观看时一直采集上传。
	screenStaleMs = 15000
	// 会话硬上限：即使一直有帧，也强制在这么久之后结束（防止忘记停）
	screenMaxLifeMs = 6 * 60 * 60 * 1000
)

type screenSession struct {
	Scale      int    `json:"scale"`
	IntervalMs int    `json:"interval_ms"`
	FrameB64   string `json:"-"`
	FrameFmt   string `json:"-"`
	FrameW     int    `json:"-"`
	FrameH     int    `json:"-"`
	Seq        uint64 `json:"-"`
	UpdatedMs  int64  `json:"-"`
	CreatedMs  int64  `json:"-"`
}

type screenHub struct {
	mu       sync.Mutex
	sessions map[string]*screenSession
}

func NewScreenHub() *screenHub {
	return &screenHub{sessions: make(map[string]*screenSession)}
}

// Start 建立/更新一个 hwid 的监控会话。scale 与 interval 会被夹到合理区间：
// 面板传错参不该让受管端以 0ms 间隔疯狂截图。
func (h *screenHub) Start(hwid string, scale, intervalMs int) {
	if scale != 1 && scale != 2 && scale != 4 && scale != 8 {
		scale = 4
	}
	if intervalMs < 100 {
		intervalMs = 100
	}
	if intervalMs > 5000 {
		intervalMs = 5000
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[hwid]
	if !ok {
		// UpdatedMs 必须在这里就置为当前时间：
		// 它原本只在收到第一帧时才赋值，于是新会话的 UpdatedMs=0，
		// 实测症状：服务端日志里"开始监控"与"会话静默超时"相隔 2 秒。
		now := time.Now().UnixMilli()
		s = &screenSession{CreatedMs: now, UpdatedMs: now}
		h.sessions[hwid] = s
		log.Printf("[Screen] 开始监控: hwid=%s scale=%d interval=%dms", hwid, scale, intervalMs)
	} else if s.Scale != scale || s.IntervalMs != intervalMs {
		log.Printf("[Screen] 参数变更: hwid=%s scale=%d->%d interval=%d->%d",
			hwid, s.Scale, scale, s.IntervalMs, intervalMs)
	}
	s.Scale = scale
	s.IntervalMs = intervalMs
}

func (h *screenHub) Stop(hwid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.sessions[hwid]; !ok {
		return false
	}
	delete(h.sessions, hwid)
	log.Printf("[Screen] 停止监控: hwid=%s", hwid)
	return true
}

// 返回 ok=false 表示受管端应停止采集线程。
func (h *screenHub) Spec(hwid string) (scale, intervalMs int, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, exists := h.sessions[hwid]
	if !exists {
		return 0, 0, false
	}
	// 防御：UpdatedMs==0 表示"还没被初始化过"，绝不能当成"很久没更新"。
	// 这类"0 值恰好满足超时条件"的坑在时间戳字段上特别容易犯。
	if s.UpdatedMs > 0 && time.Now().UnixMilli()-s.UpdatedMs > screenStaleMs {
		// 静默超时：面板已不取帧，别让受管端白采白传
		delete(h.sessions, hwid)
		log.Printf("[Screen] 会话静默超时，已停止: hwid=%s", hwid)
		return 0, 0, false
	}
	return s.Scale, s.IntervalMs, true
}

// StoreFrame 覆盖式存入最新一帧（旧帧直接被丢弃，不排队）
func (h *screenHub) StoreFrame(hwid, b64, fmtName string, w, hgt int, seq uint64) bool {
	if len(b64) > screenMaxFrameBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[hwid]
	if !ok {
		return false // 没有会话（已停止）：直接丢弃，不要偷偷建会话
	}
	s.FrameB64 = b64
	s.FrameFmt = fmtName
	s.FrameW = w
	s.FrameH = hgt
	s.Seq = seq
	s.UpdatedMs = time.Now().UnixMilli()
	return true
}

// Latest 取最新一帧。ageMs 用于让面板区分"正在刷新"与"信号中断"。
func (h *screenHub) Latest(hwid string) (b64, fmtName string, w, hgt int, seq uint64, ageMs int64, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, exists := h.sessions[hwid]
	if !exists {
		return "", "", 0, 0, 0, 0, false
	}
	if s.Seq == 0 {
		return "", "", 0, 0, 0, 0, true // 会话在、但还没收到第一帧
	}
	return s.FrameB64, s.FrameFmt, s.FrameW, s.FrameH, s.Seq,
		time.Now().UnixMilli() - s.UpdatedMs, true
}

// Active 该 hwid 是否正在监控（给 /api/agents 之类的地方用）
func (h *screenHub) Active(hwid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.sessions[hwid]
	return ok
}

// Cleanup 定期清理僵尸会话（静默超时 / 超过硬上限）
func (h *screenHub) Cleanup() {
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	for hwid, s := range h.sessions {
		stale := s.UpdatedMs > 0 && now-s.UpdatedMs > screenStaleMs
		if stale || now-s.CreatedMs > screenMaxLifeMs {
			delete(h.sessions, hwid)
			log.Printf("[Screen] 清理会话: hwid=%s（静默 %dms）", hwid, now-s.UpdatedMs)
		}
	}
}
