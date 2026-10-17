package main

// ═══════════════════════════════════════════════════════════════════════════
// 策略/设置目录（路径 A）
//
// 分工：**面板只负责"拨开关"，服务端负责把它变成一份 .reg 并写进期望态。**
// 为什么这么分：生成文件、写 filestore、写期望态都是服务端擅长的事；
// 若让面板自己走上传接口，QML 里就会塞满协议细节（上传怎么编码、名字怎么拼…）。
//
// 关键收益：走的是**已有的 reg 链** —— 于是自动获得
//   按值校验（今天刚做的）+ 漂移自愈 + .reg 备份回滚，受管端一行都不用改。
//
// 清单来源：filestore/policies.json —— 放文件而不是内置，改清单不用重编译。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"log"
	"time"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PolicySetting 一个"可拨的设置项"。
//
// 策略的"开"不一定是 1。例如 HideFileExt=0 才是"显示扩展名"（这才是开）。
// 猜错的表现是"开关拨到开、系统行为却是关" —— 这种错很难被发现。
type PolicySetting struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Type    string   `json:"type"` // bool | enum | int | string
	Hive    string   `json:"hive"` // HKLM | HKCU
	Path    string   `json:"path"`
	Value   string   `json:"value"`
	RegType string   `json:"reg_type"` // dword | sz
	On      string   `json:"on,omitempty"`
	Off     string   `json:"off,omitempty"`
	Options []string `json:"options,omitempty"`
	Note    string   `json:"note,omitempty"`
	// Excludes 声明与哪些**设置项**互斥（如"开日志 ⇄ 关日志"）。
	// 语义：本项处于"启用"状态时，它列出的那些项**自动取消**（从本次下发里剔除）。
	Excludes []string `json:"excludes,omitempty"`
	// FormOnly: this setting belongs to a form only. The panel hides it from the
	// settings list because the hardening direction is applied by the lockdown form.
	FormOnly bool `json:"form_only"`
}

// PolicyPack 是一组预置值的**策略包**（如"隐私加固（全开）"）。
//
// 为什么放在服务端展开、而不是让面板发多条期望态：一个包展开成**同一份 .reg**，
type PolicyPack struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Note   string            `json:"note,omitempty"`
	Values map[string]string `json:"values"`
}

// PolicyAsset 是「非注册表」的策略资产：它带**载荷正文**，由服务端写成文件，
// 再以对应的 apply 类型进期望态。三种 kind 的载荷契约都核对过客户端实现：
// 为什么值得单独一类：这三样**reg 表达不了** —— 服务要"当场停+禁用"（不是等重启）、
// 口令策略只有 secedit 能做、hosts 屏蔽是文本而非常量。
type PolicyAsset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Kind      string `json:"kind"` // ps1 | hosts | secedit
	Note      string `json:"note,omitempty"`
	Content   string `json:"content"`
	Ext       string `json:"ext,omitempty"`
	TargetDir string `json:"target_dir,omitempty"`
	ApplyArgs string `json:"apply_args,omitempty"`
	Default bool `json:"default,omitempty"`
	// Excludes 声明与哪些资产**互斥**（对偶对：权限回收 ⇄ 提升权限、布防 ⇄ 撤防）。
	Excludes []string `json:"excludes,omitempty"`
	// （2026-10-10 用户反馈：像 autorun_harden / daily_demote 这些"一键锁死"本来就会下发，
	FormOnly bool `json:"form_only,omitempty"`
	// 起因（2026-10-10 实测）：gate_rotate_arm 需要 gate.secret，而 secret 由 gate_arm 创建；
	Order int `json:"order,omitempty"`
}

type PolicyCatalog struct {
	Settings []PolicySetting `json:"settings"`
	Packs    []PolicyPack    `json:"packs"`
	Assets   []PolicyAsset   `json:"assets"`
}

func loadPolicyCatalog(filestoreDir string) (PolicyCatalog, error) {
	var c PolicyCatalog
	p := filepath.Join(filestoreDir, "policies.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return c, err
	}
	// 兼容两种形状：早期是**裸数组**（只有设置项），现在推荐
	// {"settings":[...],"packs":[...]}。两种都读，避免改一次格式就让线上清单读不出来。
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &c.Settings); err != nil {
			return c, err
		}
		return c, nil
	}
	// 对象形状（现在的正式格式）: {"settings":[...],"packs":[...]}
	// 注意这里必须 Unmarshal 到 **c**（整体），不能到 c.Settings ——
	// 我第一次只改了上面那个分支、漏了这行，于是对象形状直接报
	// "cannot unmarshal object into Go value of type []main.PolicySetting"。
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

// buildRegFromValues 把 {设置项id: 取值} 变成一份 .reg 文本。
//
// 两个必须处理的细节：
//   ① **按 hive+path 分组**：同一路径下的多个值要写进同一个 [键] 段，
//      否则会出现同一个键段出现多次（reg import 能容忍，但不是合法写法，也不好读）。
//   ② dword 必须格式化成 8 位十六进制（reg 文件的约定）。

// 赢家判定（确定性、可解释）：
func xorFilterSettings(cat PolicyCatalog, values map[string]string) map[string]string {
	byID := map[string]PolicySetting{}
	order := map[string]int{}
	for i, s := range cat.Settings {
		byID[s.ID] = s
		if _, dup := order[s.ID]; !dup {
			order[s.ID] = i
		}
	}
	enabled := func(id string, v string) bool {
		s, ok := byID[id]
		return ok && s.On != "" && v == s.On
	}
	drop := map[string]bool{}
	// ── ① 按注册表键去重：同一 (hive,path,value) 只留赢家 ──
	type slot struct{ ids []string }
	groups := map[string]*slot{}
	for id := range values {
		s, ok := byID[id]
		if !ok {
			continue
		}
		k := strings.ToLower(s.Hive + "|" + s.Path + "|" + s.Value)
		if groups[k] == nil {
			groups[k] = &slot{}
		}
		groups[k].ids = append(groups[k].ids, id)
	}
	for _, g := range groups {
		if len(g.ids) < 2 {
			continue
		}
		win := g.ids[0]
		for _, id := range g.ids[1:] {
			switch {
			case enabled(id, values[id]) && !enabled(win, values[win]):
				win = id // 启用的优先 
			case enabled(id, values[id]) == enabled(win, values[win]) && order[id] < order[win]:
				win = id // 同状态  目录靠前的优先 
			}
		}
		for _, id := range g.ids {
			if id != win {
				drop[id] = true
			}
		}
	}
	for id := range values {
		s, ok := byID[id]
		if !ok {
			continue
		}
		for _, ex := range s.Excludes {
			if ex == id || values[ex] == "" {
				continue
			}
			if enabled(id, values[id]) && !enabled(ex, values[ex]) {
				drop[ex] = true
			}
		}
	}
	if len(drop) == 0 {
		return values
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		if drop[k] {
			continue
		}
		out[k] = v
	}
	return out
}

func buildRegFromValues(cat PolicyCatalog, values map[string]string) (string, []string, error) {

	// ── 设置级互斥（自动取消）2026-10-11 ──────────────────────────────────
	values = xorFilterSettings(cat, values)

	byID := map[string]PolicySetting{}
	for _, s := range cat.Settings {
		byID[s.ID] = s
	}
	// 先取出所有被显式赋值的项，并按 键 分组（配对的顺序要稳定，便于比对 diff）
	type kv struct{ name, data string }
	groups := map[string][]kv{}
	var groupOrder []string
	var applied []string
	var ids []string
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s, ok := byID[id]
		if !ok {
			return "", nil, fmt.Errorf("清单里没有这个设置项: %s", id)
		}
		raw := strings.TrimSpace(values[id])
		if raw == "" {
			continue // 空值 = 不改这一项
		}
		// 允许调用方用语义化写法 on/off/true/false，由清单里的 on/off 决定实际写什么。
		// 光看值根本没法用，写反了还不会有任何报错（只会"策略没生效"）。
		// 面板的复选框本来就发的是清单值，这条只是让 CLI / 脚本也安全。
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "on", "true", "开", "启用":
			if s.On == "" {
				return "", nil, fmt.Errorf("%s 没声明 on 值，不能用 on/true 下发", s.Name)
			}
			raw = s.On
		case "off", "false", "关", "禁用":
			if s.Off == "" {
				return "", nil, fmt.Errorf("%s 没声明 off 值，不能用 off/false 下发", s.Name)
			}
			raw = s.Off
		}

		// "-" 是 .reg 的**删除该值**语义（`"Name"=-`）。
		// 客户端侧的校验已经支持它（RegValueWant.del：期望"这个值不存在"），
		// 所以这里一旦生成，删除结果也会被按值校验 + 漂移自愈照看。
		if raw == "-" {
			key := regHiveFull(s.Hive) + "\\" + strings.Trim(s.Path, "\\")
			if _, seen := groups[key]; !seen {
				groupOrder = append(groupOrder, key)
			}
			groups[key] = append(groups[key], kv{name: s.Value, data: "-"})
			applied = append(applied, s.ID+"=(删除)")
			continue
		}
		key := regHiveFull(s.Hive) + "\\" + strings.Trim(s.Path, "\\")
		var data string
		switch s.RegType {
		case "dword":
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return "", nil, fmt.Errorf("%s 的值必须是整数，收到 %q", s.Name, raw)
			}
			if n < 0 {
				n += 1 << 32 // 允许 -1 这种写法（= 0xFFFFFFFF）
			}
			data = fmt.Sprintf("dword:%08x", uint32(n))
		case "sz", "":
			data = "\"" + strings.ReplaceAll(raw, "\"", "\\\"") + "\""
		default:
			return "", nil, fmt.Errorf("%s 的 reg_type 不支持: %s", s.Name, s.RegType)
		}
		if _, seen := groups[key]; !seen {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], kv{name: s.Value, data: data})
		applied = append(applied, s.ID+"="+raw)
	}
	if len(groupOrder) == 0 {
		return "", nil, fmt.Errorf("没有任何要下发的项（所有值都是空的）")
	}
	var b strings.Builder
	b.WriteString("Windows Registry Editor Version 5.00\r\n")
	for _, key := range groupOrder {
		b.WriteString("\r\n[" + key + "]\r\n")
		for _, item := range groups[key] {
			if item.name == "" {
				b.WriteString("@=" + item.data + "\r\n")
			} else {
				b.WriteString("\"" + item.name + "\"=" + item.data + "\r\n")
			}
		}
	}
	return b.String(), applied, nil
}


//
// 反解的依据很硬：那份 .reg 就是我们自己生成的（见 buildRegFromValues）。
func parseRegBack(text string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 || section == "" {
			continue
		}
		name := strings.Trim(line[:eq], "\"")
		val := strings.TrimSpace(line[eq+1:])
		// 去掉 regHiveFull 展开出来的长名，统一回短名（与清单一致）
		sec := section
		for long, short := range map[string]string{
			"hkey_local_machine": "hklm", "hkey_current_user": "hkcu",
			"hkey_classes_root": "hkcr", "hkey_users": "hku",
			"hkey_current_config": "hkcc",
		} {
			if strings.HasPrefix(sec, long) {
				sec = short + sec[len(long):]
				break
			}
		}
		out[sec+"|"+strings.ToLower(name)] = val
	}
	return out
}

// regValueToSemantic 把 .reg 里的字面值还原成清单语义（on/off 或原始数字/文本）。
// 为什么还原成 on/off：面板的复选框只认 on/off —— 直接给它 "0"/"1" 会出现
// "1 在两个项里含义相反"那个老问题（显示隐藏文件 1=开，禁用 LLMNR 1=关）。
// regValueRaw 把 .reg 里的字面值归一化成**控件的原始取值**：
// 为什么**不**映射成 on/off：面板的复选框/下拉是拿 values[id] 去比 modelData.on / options 的，
// 至于"同一个 1 含义相反"那个坑，是在**用户输入**侧解决的（API 接受 on/off/true/false 并由清单翻译），
// 与"把真实值读回来给控件"是两件事，不该混。
func regValueRaw(raw string) string {
	v := strings.TrimSpace(raw)
	lv := strings.ToLower(v)
	if strings.HasPrefix(lv, "dword:") {
		if n, err := strconv.ParseInt(strings.TrimPrefix(lv, "dword:"), 16, 64); err == nil {
			return strconv.FormatInt(n, 10)
		}
	}
	if len(v) >= 2 && strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		return v[1 : len(v)-1]
	}
	return v
}

// registerPolicyRoutes 挂上策略目录相关的两个入口。
//
// 只做两件事：读清单、以及"把开关变成 .reg + 写期望态"。
// 不做"读回真机当前值" —— 那必须经受管端（服务端看不到远端注册表），
// 属于下一版的事；这一版不假装能做。
func registerPolicyRoutes(mux *http.ServeMux, sessions *SessionManager,
	filestoreDir string,
	desired *DesiredHub, agents *AgentRegistry) {

	mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		cat, err := loadPolicyCatalog(filestoreDir)
		if err != nil {
			// 清单缺失要说清是"文件没有"还是"格式不对"，别让面板显示成"没有设置项"
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "settings": []interface{}{},
				"error": "读 policies.json 失败: " + err.Error(),
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "settings": cat.Settings, "packs": cat.Packs, "assets": cat.Assets,
		})
	})


	mux.HandleFunc("/api/policies/current", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		hwid := r.URL.Query().Get("hwid")
		if hwid == "" {
			writeJSON(w, 400, map[string]string{"error": "缺少 hwid"})
			return
		}
		cat, err := loadPolicyCatalog(filestoreDir)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": true, "values": map[string]string{},
				"error": "读 policies.json 失败: " + err.Error()})
			return
		}
		raw, rerr := os.ReadFile(filepath.Join(filestoreDir, "policies-"+hwid+".reg"))
		if rerr != nil {
			// 这台机还没下发过任何策略 —— 不是错误，如实回空
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "values": map[string]string{}, "dispatched": []string{},
				"note": "这台机还没有策略文件（从未下发过）"})
			return
		}
		back := parseRegBack(string(raw))
		vals := map[string]string{}
		var dispatched []string
		for _, s := range cat.Settings {
			k := strings.ToLower(strings.Trim(s.Hive, "\\")+"\\"+strings.Trim(s.Path, "\\")) +
				"|" + strings.ToLower(s.Value)
			if v, ok := back[k]; ok {
				vals[s.ID] = regValueRaw(v)
				dispatched = append(dispatched, s.ID)
			}
		}
		var pendAt, pendIn int64
		if p := desired.PendingFor(hwid); p != nil {
			pendAt = p.AtMs
			pendIn = (p.AtMs - time.Now().UnixMilli()) / 1000
			if pendIn < 0 { pendIn = 0 }
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "values": vals, "dispatched": dispatched,
			"pending_revert_at": pendAt, "pending_in_s": pendIn,
			"note": "values = 这台机当前那份策略 .reg 的实际内容（面板据此初始化控件）",
		})
	})

	mux.HandleFunc("/api/policies/apply", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			HWID      string            `json:"hwid"`
			Values    map[string]string `json:"values"`
			Pack      string            `json:"pack"` // 策略包 id（与 values 可同时给，values 优先）
			Asset     string            `json:"asset"` // 策略资产 id（走非注册表 apply）
			TTLSeconds int64            `json:"ttl_seconds"` // >0  到点自动恢复成"本次应用前的期望态"（临时临时授权）
			TargetDir string            `json:"target_dir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if body.HWID == "" {
			writeJSON(w, 400, map[string]string{"error": "缺少 hwid"})
			return
		}
		if !agents.HasKey(body.HWID) {
			writeJSON(w, 404, map[string]string{"error": "未知的 hwid: " + body.HWID})
			return
		}
		cat, err := loadPolicyCatalog(filestoreDir)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "读 policies.json 失败: " + err.Error()})
			return
		}
		// 临时临时授权：在改动**之前**拍快照 —— 到点恢复的就是它。顺序很关键：
		// 改动后再拍等于"恢复到改动后的状态"，那就等于没恢复。
		beforeOf := func(hwid string) []DesiredItem {
			cur := desired.Get(hwid)
			if cur == nil { return nil }
			cp := make([]DesiredItem, len(cur.Items))
			copy(cp, cur.Items)
			return cp
		}
				// snapFiles 在覆盖**之前**把目标文件的字节存下来（ttl<=0 时不做，零开销）。
		snapFiles := func(names ...string) []FileSnap {
			if body.TTLSeconds <= 0 {
				return nil
			}
			var out []FileSnap
			for _, n := range names {
				if n == "" {
					continue
				}
				b, err := os.ReadFile(filepath.Join(filestoreDir, n))
				out = append(out, FileSnap{Name: n, Bytes: b, Existed: err == nil})
			}
			return out
		}
		scheduleRevert := func(hwid, label string, before []DesiredItem, files []FileSnap) (int64, int64) {
			if body.TTLSeconds <= 0 { return 0, 0 }
			ttl := body.TTLSeconds
			if ttl > 24*3600 { ttl = 24 * 3600 }   // 上限一天，避免写出"忘了关"的永久临时授权
			at := time.Now().UnixMilli() + ttl*1000
			desired.AddPending(hwid, at, label, before, files)
			log.Printf("[Desired] 临时临时授权 %s：%d 秒后自动恢复成 %d 项（%s）", hwid, ttl, len(before), label)
			return at, ttl
		}

		// ── 策略资产：把载荷写成文件，再以对应 apply 进期望态 ──
		if body.Asset != "" {
			var a *PolicyAsset
			for i := range cat.Assets {
				if cat.Assets[i].ID == body.Asset {
					a = &cat.Assets[i]
					break
				}
			}
			if a == nil {
				writeJSON(w, 400, map[string]string{"error": "没有这个策略资产: " + body.Asset})
				return
			}
			if a.Kind == "" || a.Content == "" {
				writeJSON(w, 500, map[string]string{"error": "资产 " + a.ID + " 缺 kind 或 content"})
				return
			}
			ext := a.Ext
			if ext == "" {
				ext = map[string]string{"ps1": ".ps1", "hosts": ".hosts", "secedit": ".inf"}[a.Kind]
			}
			if ext == "" {
				ext = ".txt"
			}
			name := "policy-" + a.ID + ext
			full := filepath.Join(filestoreDir, name)
			tmp := full + ".tmp"
			snapAsset := snapFiles(name)
			if err := os.WriteFile(tmp, []byte(a.Content), 0644); err != nil {
				writeJSON(w, 500, map[string]string{"error": "写资产失败: " + err.Error()})
				return
			}
			if err := os.Rename(tmp, full); err != nil {
				writeJSON(w, 500, map[string]string{"error": "替换资产失败: " + err.Error()})
				return
			}
			target := strings.TrimSpace(a.TargetDir)
			if target == "" {
				target = `C:\ProgramData\r6m-policies`
			}
			// 为什么（2026-10-09 实测事故）：资产是"一次性动作"，但原先只按 From 去重
			//   而资产之间存在**互斥对偶**：admin_group_revoke ⇄ admin_group_restore、
			//   gate_arm ⇄ autorun_off；还有带副作用的（gate_test 会拉起 notepad）。
			//   症状就是用户"点了归还管理员组却没生效" —— 收回那条还在，后面又收了回去。
			//
			//   daily_demote（日常账号权限回收）/ gate_rotate_arm（密码轮换）/ desk_pw_off /
			//   autorun_harden / ps_v2_disable / ensure_dirs 这些是"机器该有的样子"，
			from := "policy:asset:" + a.ID
			beforeAsset := beforeOf(body.HWID)
			// 目录里声明为不变式 / 被本次排除的资产集合
			persistIDs := map[string]bool{}
			for i := range cat.Assets {
				if cat.Assets[i].Default {
					persistIDs[cat.Assets[i].ID] = true
				}
			}
			for _, ex := range a.Excludes {
				delete(persistIDs, ex)
			}
			var kept []DesiredItem
			if cur := desired.Get(body.HWID); cur != nil {
				for _, it := range cur.Items {
					if !strings.HasPrefix(it.From, "policy:asset:") {
						kept = append(kept, it)   // 非资产来源：不动 
						continue
					}
					oldID := strings.TrimPrefix(it.From, "policy:asset:")
					if oldID == a.ID {
						continue                   // 当前这个稍后重新追加（拿最新 sha ）
					}
					if persistIDs[oldID] {
						kept = append(kept, it)    // 不变式：保留 （下一轮仍会被重放）
						continue
					}
				}
			}
			// 资产条目也要带 sha256：否则客户端只能用"本地有没有记录过"当判据
			asum := sha256.Sum256([]byte(a.Content))
			kept = append(kept, DesiredItem{
				FileName: name, TargetDir: target, Apply: a.Kind,
				ApplyArgs: a.ApplyArgs, From: from,
				SHA256: hex.EncodeToString(asum[:]),
				RunID:  strconv.FormatInt(time.Now().UnixNano(), 10),
			})
			orderOf := map[string]int{}
			for i := range cat.Assets {
				orderOf[cat.Assets[i].ID] = cat.Assets[i].Order
			}
			var head, tail []DesiredItem
			for _, it := range kept {
				if strings.HasPrefix(it.From, "policy:asset:") {
					tail = append(tail, it)
				} else {
					head = append(head, it)
				}
			}
			sort.SliceStable(tail, func(i, j int) bool {
				oi := orderOf[strings.TrimPrefix(tail[i].From, "policy:asset:")]
				oj := orderOf[strings.TrimPrefix(tail[j].From, "policy:asset:")]
				return oi < oj
			})
			kept = append(head, tail...)
			rev := desired.Set(body.HWID, kept)
			revAt, revIn := scheduleRevert(body.HWID, "asset:"+a.ID, beforeAsset, snapAsset)
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "asset": a.ID, "asset_name": a.Name, "kind": a.Kind,
				"revert_at_ms": revAt, "revert_in_s": revIn,
				"file": name, "bytes": len(a.Content), "rev": rev, "target_dir": target,
				"note": "已写入资产并以 apply=" + a.Kind + " 进期望态；受管端下一轮收敛",
			})
			return
		}

		values, packName := body.Values, ""
		if body.Pack != "" {
			found := false
			for _, p := range cat.Packs {
				if p.ID != body.Pack {
					continue
				}
				// 合并：包里给打底，调用方显式给的值覆盖它（便于"用包打底再微调"）
				m := map[string]string{}
				for k, v := range p.Values {
					m[k] = v
				}
				for k, v := range body.Values {
					m[k] = v
				}
				values, packName, found = m, p.Name, true
				break
			}
			if !found {
				writeJSON(w, 400, map[string]string{"error": "没有这个策略包: " + body.Pack})
				return
			}
		}
		reg, applied, err := buildRegFromValues(cat, values)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}

		// 文件名带 hwid：每台机器一份，互不干扰（也便于"谁的策略是什么"一眼看出）
		name := "policies-" + body.HWID + ".reg"
		// 落盘前先写临时文件再改名：写一半的 .reg 被当成好文件比"没写"更糟
		full := filepath.Join(filestoreDir, name)
		tmp := full + ".tmp"
		snapVals := snapFiles(name)
		if err := os.WriteFile(tmp, []byte(reg), 0644); err != nil {
			writeJSON(w, 500, map[string]string{"error": "写策略文件失败: " + err.Error()})
			return
		}
		if err := os.Rename(tmp, full); err != nil {
			writeJSON(w, 500, map[string]string{"error": "替换策略文件失败: " + err.Error()})
			return
		}

		target := strings.TrimSpace(body.TargetDir)
		if target == "" {
			target = `C:\ProgramData\r6m-policies` // 默认落点，可在请求里覆盖
		}
		// 读-改-写期望态：只替换 from==policy:catalog 的那一条，
		// 别的来源（面板投放、插件一键装）的条目不碰。
		//   触发条件 = **全新受管端第一次下发策略包** —— 主机一直没暴露是因为它早被下发过，
		var items []DesiredItem
		if cur := desired.Get(body.HWID); cur != nil {
			items = cur.Items
		}
		var kept []DesiredItem
		for _, it := range items {
			if it.From == "policy:catalog" {
				continue
			}
			kept = append(kept, it)
		}
		// **必须带上内容的 sha256**：期望态条目只是一个"文件名"引用，
		// （实测：加了 cortana_off 却没 bump；而 DesiredItem.SHA256 这个字段
		//   本来就是为这个设计的 ——"版本判据：不一致就换" —— 却一直是空值）
		sum := sha256.Sum256([]byte(reg))
		kept = append(kept, DesiredItem{
			FileName: name, TargetDir: target, Apply: "reg", From: "policy:catalog",
			SHA256: hex.EncodeToString(sum[:]),
		})
		beforeVals := beforeOf(body.HWID)
		rev := desired.Set(body.HWID, kept)
		label := "catalog"
		if packName != "" { label = "pack:" + packName }
		revAt, revIn := scheduleRevert(body.HWID, label, beforeVals, snapVals)
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "file": name, "bytes": len(reg), "rev": rev,
			"applied": applied, "target_dir": target, "pack_name": packName,
			"revert_at_ms": revAt, "revert_in_s": revIn,
			"note": "已生成 .reg 并写进期望态；受管端下一轮 poll 会收敛（含按值校验与漂移自愈）",
		})
	})
}

// regHiveFull 把短 hive 名展开成全名。
//
//   reg.exe import 只认 [HKEY_LOCAL_MACHINE\...] 这种**全名**；
// 未知 hive 原样输出（让它被 reg.exe 拒掉），而不是猜一个可能更错的名字。
func regHiveFull(h string) string {
	switch strings.ToUpper(strings.TrimSpace(h)) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKEY_LOCAL_MACHINE"
	case "HKCU", "HKEY_CURRENT_USER":
		return "HKEY_CURRENT_USER"
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "HKEY_CLASSES_ROOT"
	case "HKU", "HKEY_USERS":
		return "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return "HKEY_CURRENT_CONFIG"
	}
	return h
}
