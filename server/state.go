package main

// ═══════════════════════════════════════════════════════════════════════════
// state.go —— 服务端状态自启动配置（agent 注册表 + per-agent 密钥）
//
//   AgentRegistry 原来是**纯内存**的，服务端一重启（发版、崩溃、设备断电）
//   所有已登记 hwid 与 per-agent 密钥全部丢失。后果不是"重新注册一次"这么轻：
//   只能逐台手工重启。对"长期滞留"的用法来说这是致命的。
//
// 落盘内容（state.json）：
//   agents          hwid -> {user, os, ip, lastSeen, integrity}
//   clear_integrity hwid -> 待下发的解除安全隔离标记（运维决定必须扛过重启）
//   version         结构版本，便于日后迁移
//   （online 刻意不自启动配置：它是瞬时状态，重启后应由心跳重新点亮）
//
// 静态保护：
//   per-agent 密钥是凭据，不能明文躺在盘上。用 state.key 里的随机 32 字节密钥
//   做 AES-256-GCM 加密（GCM 带认证，顺带防篡改）。
//   **诚实说明边界**：state.key 与 state.json 同目录，能读整机的人两个都能读，
//   所以它防的是"状态文件被单独拷走/进备份/误发/被截图"，防不住拿到 root 的人。
//   要防后者只能外置 KMS 或口令派生，代价是"重启需人工输入口令"——与"长期
//   无人值守滞留"的目标直接冲突，故不采用。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateFormatVersion = 1

type stateSnapshot struct {
	Version        int               `json:"version"`
	SavedAt        int64             `json:"saved_at"`
	Keys           map[string]string `json:"keys"`
	Agents         map[string]Agent  `json:"agents"`
	ClearIntegrity map[string]bool   `json:"clear_integrity,omitempty"`
}

// serverStateDir 状态文件与证书、引导密钥放同一目录（可执行文件所在目录）。
// 与 loadOrCreateAgentKey / ensureCert 保持一致的约定：整个部署是"自包含目录"，
// 所以只要固定 PROG 路径，状态就跟着走。
func serverStateDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exePath)
}

// loadOrCreateStateKey 读取或生成 state.key（32 字节 AES 密钥，0600）。
// 复用已存在的旧文件（例如历史遗留的 state.key）时必须校验长度：
// 长度不对说明不是我们生成的，宁可按"没有密钥"处理并另存新文件，
// 也不要拿它去解密（会得到难以理解的 GCM 认证失败）。
func loadOrCreateStateKey(dir string) ([]byte, error) {
	p := filepath.Join(dir, "state.key")
	if data, err := os.ReadFile(p); err == nil {
		raw := strings.TrimSpace(string(data))
		// 兼容两种形态：32 字节 hex（64 字符）或原始 32 字节
		if len(raw) == 64 {
			if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
				return b, nil
			}
		}
		if len(data) == 32 {
			return data, nil
		}
		log.Printf("[State] state.key 长度/格式不符合预期(%d 字节)，将重新生成（旧文件改名保留）", len(data))
		_ = os.Rename(p, p+fmt.Sprintf(".bad-%d", time.Now().Unix()))
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("生成状态密钥失败: %w", err)
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)), 0600); err != nil {
		return nil, fmt.Errorf("写入 state.key 失败: %w", err)
	}
	return b, nil
}

func sealState(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// 输出 = nonce || 密文||tag
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func openState(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("状态文件太短，不是有效的加密状态")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// 直接覆写会在"写一半断电"时留下半个文件，下次启动就读不出来了。
func saveStateFile(dir string, key []byte, snap stateSnapshot) error {
	snap.Version = stateFormatVersion
	snap.SavedAt = time.Now().UnixMilli()
	plain, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("序列化状态失败: %w", err)
	}
	blob, err := sealState(key, plain)
	if err != nil {
		return fmt.Errorf("加密状态失败: %w", err)
	}

	final := filepath.Join(dir, "state.json")
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建临时状态文件失败: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(tmp) // pj-guard:allow 自己的临时文件，写失败后清理是必要的
		return fmt.Errorf("写临时状态文件失败: %w", err)
	}
	// 落盘自启动配置（eMMC 上尤其重要：rename 之后才断电也不算丢）
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp) // pj-guard:allow 同上
		return fmt.Errorf("fsync 状态文件失败: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp) // pj-guard:allow 同上
		return fmt.Errorf("关闭临时状态文件失败: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp) // pj-guard:allow 同上
		return fmt.Errorf("替换状态文件失败: %w", err)
	}
	return nil
}

// loadStateFile 读取状态。任何失败都**不阻止启动**：改名保留坏文件后返回空状态。
// 理由：服务端能起来比状态完整更重要（起不来就什么都做不了），而坏文件必须
// 留住以便人工排查——直接覆盖会销毁唯一的现场。
func loadStateFile(dir string, key []byte) (stateSnapshot, error) {
	empty := stateSnapshot{
		Keys:           map[string]string{},
		Agents:         map[string]Agent{},
		ClearIntegrity: map[string]bool{},
	}
	p := filepath.Join(dir, "state.json")
	blob, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return empty, nil // 首次启动，正常
		}
		return empty, fmt.Errorf("读取状态文件失败: %w", err)
	}
	plain, err := openState(key, blob)
	if err != nil {
		bad := p + fmt.Sprintf(".bad-%d", time.Now().Unix())
		if rerr := os.Rename(p, bad); rerr != nil {
			log.Printf("[State] 状态文件无法解密(%v)，且改名失败(%v)", err, rerr)
		} else {
			log.Printf("[State] 状态文件无法解密(%v)，已改名保留为 %s（注意：这会导致本次启动视为全新部署）", err, filepath.Base(bad))
		}
		return empty, nil
	}
	var snap stateSnapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		bad := p + fmt.Sprintf(".bad-%d", time.Now().Unix())
		_ = os.Rename(p, bad)
		log.Printf("[State] 状态文件内容损坏(%v)，已改名保留为 %s", err, filepath.Base(bad))
		return empty, nil
	}
	if snap.Keys == nil {
		snap.Keys = map[string]string{}
	}
	if snap.Agents == nil {
		snap.Agents = map[string]Agent{}
	}
	if snap.ClearIntegrity == nil {
		snap.ClearIntegrity = map[string]bool{}
	}
	if snap.Version > stateFormatVersion {
		log.Printf("[State] 状态文件版本(%d)高于本程序支持的版本(%d)，仍尝试按当前格式读取", snap.Version, stateFormatVersion)
	}
	return snap, nil
}
