package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trymonoly/K8sPenTool-ng/internal/ai"
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

type AISession struct {
	ID        string             `json:"id"`
	TargetID  string             `json:"target_id"`
	Plan      *engine.AttackPlan `json:"plan,omitempty"`
	Status    string             `json:"status"`
	History   []AIHistoryEntry   `json:"history"`
	CreatedAt time.Time          `json:"created_at"`
	Auth      *ai.AuthCreds      `json:"auth"`
	mu        sync.RWMutex
}

type AIHistoryEntry struct {
	Role      string      `json:"role"`
	Content   string      `json:"content"`
	ToolCalls interface{} `json:"tool_calls,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type AIHandler struct {
	sessions    map[string]*AISession
	mu          sync.RWMutex
	llmClient   *ai.LLMClient
	llmConfig   *ai.LLMConfig
	sessionsDir string
}

func NewAIHandler() *AIHandler {
	h := &AIHandler{
		sessions: make(map[string]*AISession),
	}
	h.initPersistence()
	return h
}

func (h *AIHandler) initPersistence() {
	home, _ := os.UserHomeDir()
	h.sessionsDir = filepath.Join(home, ".k8spen", "ai_sessions")
	os.MkdirAll(h.sessionsDir, 0700)
	// 加载已有会话
	entries, _ := os.ReadDir(h.sessionsDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			path := filepath.Join(h.sessionsDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil { continue }
			var s AISession
			if err := json.Unmarshal(data, &s); err != nil { continue }
			s.mu = sync.RWMutex{}
			h.sessions[s.ID] = &s
		}
	}
	log.Printf("[AI] 已加载 %d 个历史会话", len(h.sessions))
}

func (h *AIHandler) saveSession(session *AISession) {
	session.mu.RLock()
	data, err := json.Marshal(session)
	session.mu.RUnlock()
	if err != nil { return }
	path := filepath.Join(h.sessionsDir, session.ID+".json")
	os.WriteFile(path, data, 0600)
}

func (h *AIHandler) deleteSessionFile(id string) {
	path := filepath.Join(h.sessionsDir, id+".json")
	os.Remove(path)
}

func (h *AIHandler) GetOrCreateLLMClient() *ai.LLMClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.llmClient == nil {
		h.llmConfig = ai.LoadConfig()
		h.llmClient = ai.NewLLMClient(h.llmConfig)
	}
	return h.llmClient
}

func (h *AIHandler) GetConfig(c *gin.Context) {
	cfg := ai.LoadConfig()
	c.JSON(http.StatusOK, gin.H{
		"provider": cfg.Provider, "model": cfg.Model,
		"base_url": cfg.BaseURL, "has_api_key": cfg.APIKey != "",
	})
}

func (h *AIHandler) UpdateConfig(c *gin.Context) {
	var req struct {
		Provider string  `json:"provider"`
		Model    string  `json:"model"`
		APIKey   string  `json:"api_key"`
		BaseURL  string  `json:"base_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	cfg := ai.LoadConfig()
	if req.Provider != "" { cfg.Provider = ai.ProviderType(req.Provider) }
	if req.Model != "" { cfg.Model = req.Model }
	if req.APIKey != "" { cfg.APIKey = req.APIKey }
	if req.BaseURL != "" { cfg.BaseURL = req.BaseURL }
	if err := ai.SaveConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	h.mu.Lock()
	h.llmConfig = cfg
	h.llmClient = ai.NewLLMClient(cfg)
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"status": "saved", "provider": string(cfg.Provider), "model": cfg.Model})
}

func (h *AIHandler) CreateSession(c *gin.Context) {
	var req struct {
		TargetID  string `json:"target_id" binding:"required"`
		Host      string `json:"host"`
		Token     string `json:"token"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		SkipTLS   bool   `json:"skip_tls"`
		TimeoutSec int   `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session := &AISession{
		ID:        uuid.New().String(),
		TargetID:  req.TargetID,
		Status:    "created",
		History:   make([]AIHistoryEntry, 0),
		CreatedAt: time.Now(),
		Auth: &ai.AuthCreds{
			Host:       req.Host,
			Token:      req.Token,
			Username:   req.Username,
			Password:   req.Password,
			SkipTLS:    req.SkipTLS,
			TimeoutSec: req.TimeoutSec,
		},
	}

	h.mu.Lock()
	h.sessions[session.ID] = session
	h.mu.Unlock()

	h.saveSession(session)
	c.JSON(http.StatusCreated, session)
}

func (h *AIHandler) GetSession(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, session)
}

func (h *AIHandler) ListSessions(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sessions := make([]*AISession, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	c.JSON(http.StatusOK, sessions)
}

func (h *AIHandler) Chat(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	var req struct {
		Message string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session.mu.Lock()
	session.History = append(session.History, AIHistoryEntry{
		Role:      "user",
		Content:   req.Message,
		Timestamp: time.Now(),
	})
	session.mu.Unlock()

	// ReAct 工具调用循环：LLM 请求工具 → 后端执行 → 结果回灌 → 直到 LLM 给出文本结论
	llm := h.GetOrCreateLLMClient()
	tools := ai.GetOpenAIToolDefinitions()

	// Guard: if Auth is nil (e.g. session reloaded from disk), we can't execute tools
	if session.Auth == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session auth credentials not available. Please create a new session."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	responseContent, traces, err := h.runToolLoop(ctx, session, tools, req.Message, llm)

	if err != nil {
		log.Printf("[AI] LLM error: %v, using fallback", err)
		responseContent = fallbackResponse(req.Message)
	}

	response := AIHistoryEntry{
		Role:      "assistant",
		Content:   responseContent,
		Timestamp: time.Now(),
	}

	session.mu.Lock()
	session.History = append(session.History, response)
	// Save individual tool call results to history for multi-turn context
	for _, t := range traces {
		session.History = append(session.History, AIHistoryEntry{
			Role:      "tool",
			Content:   t.ResultPreview,
			ToolCalls: []ai.ToolCall{{Function: ai.FunctionCallArg{Name: t.Tool, Arguments: t.Args}}},
			Timestamp: time.Now(),
		})
	}
	session.Status = "active"
	session.mu.Unlock()

	h.saveSession(session)

	c.JSON(http.StatusOK, gin.H{
		"session_id":   id,
		"response":     response,
		"tool_traces":  traces,
	})
}

// runToolLoop 执行 ReAct 循环，最多 maxRounds 轮。
func (h *AIHandler) runToolLoop(ctx context.Context, session *AISession, tools []ai.ToolDefinition, userMsg string, llm *ai.LLMClient) (string, []ai.ToolTrace, error) {
	const maxRounds = 6

	session.mu.RLock()
	messages := buildLLMMessages(session)
	session.mu.RUnlock()

	// buildLLMMessages already includes all history; userMsg was appended to session.History before this call.
	_ = userMsg // kept for signature compatibility; actual messages come from buildLLMMessages(session)

	traces := []ai.ToolTrace{}
	safety := ai.DefaultSafetyConfig()

	for round := 0; round < maxRounds; round++ {
		resp, err := llm.Chat(ctx, messages, tools)
		if err != nil {
			// 已执行的工具轨迹仍返回给前端
			if len(traces) > 0 {
				return summarizeWithTraces("（LLM 调用出错，以下为已收集到的证据）", traces), traces, nil
			}
			return "", traces, err
		}
		if len(resp.Choices) == 0 {
			break
		}
		choice := resp.Choices[0]

		// 无工具调用 → 最终文本结论
		if len(choice.Message.ToolCalls) == 0 {
			content := choice.Message.Content
			if content == "" {
				content = "(模型未返回内容)"
			}
			return content, traces, nil
		}

		// 把 assistant 的 tool_calls 加入消息流
		messages = append(messages, ai.Message{
			Role:      "assistant",
			Content:   choice.Message.Content,
			ToolCalls: choice.Message.ToolCalls,
		})

		// 逐个执行工具，结果以 tool 角色回灌
		for _, tc := range choice.Message.ToolCalls {
			// 安全闸门：使用工具的实际风险级别，而非硬编码 RiskHigh
			riskLevel := ai.GetToolRiskLevel(tc.Function.Name)
			guard := safety.CheckAction(tc.Function.Name, "", riskLevel)
			var res ai.DispatchResult
			if guard.NeedApproval {
				res = ai.DispatchResult{
					Output: "⚠️ 该操作为破坏性动作（" + tc.Function.Name + "），需人工批准后方可执行。请在 Attack Plan 中 Approve 对应步骤后重试。",
					Trace:  ai.ToolTrace{Tool: tc.Function.Name, Args: tc.Function.Arguments, ResultPreview: "需人工批准", Status: "needs_approval"},
				}
			} else {
				res = ai.Dispatch(ctx, tc, session.Auth)
			}
			traces = append(traces, res.Trace)
			log.Printf("[AI] tool %s status=%s risk=%s", tc.Function.Name, res.Trace.Status, riskLevel)

			messages = append(messages, ai.Message{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    res.Output,
			})
		}
	}

	// 达到轮次上限：基于已收集证据给结论
	if len(traces) > 0 {
		// 再问一轮让 LLM 收尾
		messages = append(messages, ai.Message{
			Role:    "user",
			Content: "已达到工具调用轮次上限。请基于上述已收集的证据，给出最终的逃逸可行性/提权可行性/Dashboard可达性分析结论（中文，分三段）。",
		})
		resp, err := llm.Chat(ctx, messages, nil)
		if err == nil && len(resp.Choices) > 0 && resp.Choices[0].Message.Content != "" {
			return resp.Choices[0].Message.Content, traces, nil
		}
		return summarizeWithTraces("（达到工具调用轮次上限，以下为已收集证据摘要）", traces), traces, nil
	}
	return "(未触发任何工具调用，也无文本结论)", traces, nil
}

func summarizeWithTraces(prefix string, traces []ai.ToolTrace) string {
	var sb strings.Builder
	sb.WriteString(prefix + "\n")
	for _, t := range traces {
		sb.WriteString("[" + t.Status + "] " + t.Tool + " " + t.Args + " → " + previewTrace(t.ResultPreview) + "\n")
	}
	return sb.String()
}

func previewTrace(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func (h *AIHandler) GeneratePlan(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	var req struct {
		Objective string `json:"objective"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Objective == "" {
		req.Objective = "Full penetration test of the target K8s cluster"
	}

	// Try LLM to generate plan, fallback to default
	llm := h.GetOrCreateLLMClient()
	messages := []ai.Message{
		{Role: "system", Content: ai.SystemPrompt + "\nGenerate an attack plan in JSON format with ordered steps."},
		{Role: "user", Content: "Generate an attack plan. Objective: " + req.Objective + ". Output as JSON with 'steps' array containing objects: {phase, tool, action, description}."},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	steps := defaultPlanSteps()
	resp, err := llm.Chat(ctx, messages, nil)
	if err == nil && len(resp.Choices) > 0 {
		content := resp.Choices[0].Message.Content
		// Try to extract JSON from response
		if parsed := parsePlanJSON(content); len(parsed) > 0 {
			steps = parsed
		}
	}

	plan := &engine.AttackPlan{
		ID:          uuid.New().String(),
		TargetID:    session.TargetID,
		Objective:   req.Objective,
		Status:      "running",
		CurrentStep: 0,
		CreatedAt:   time.Now(),
		Steps:       steps,
	}

	session.mu.Lock()
	session.Plan = plan
	session.Status = "planning"
	session.mu.Unlock()

	c.JSON(http.StatusOK, plan)
}

func (h *AIHandler) GetPlan(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	if session.Plan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no plan generated"})
		return
	}
	c.JSON(http.StatusOK, session.Plan)
}

func (h *AIHandler) ApproveStep(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	if session.Plan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no plan"})
		return
	}

	var req struct {
		StepIndex int `json:"step_index"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if req.StepIndex >= 0 && req.StepIndex < len(session.Plan.Steps) {
		session.Plan.Steps[req.StepIndex].Status = "completed"
		session.Plan.CurrentStep = req.StepIndex + 1
	}

	c.JSON(http.StatusOK, session.Plan)
}

func (h *AIHandler) StopSession(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	session.mu.Lock()
	session.Status = "stopped"
	session.mu.Unlock()
	h.saveSession(session)
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (h *AIHandler) DeleteSession(c *gin.Context) {
	id := c.Param("id")
	h.mu.Lock()
	_, ok := h.sessions[id]
	if !ok {
		h.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	delete(h.sessions, id)
	h.mu.Unlock()
	h.deleteSessionFile(id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// buildLLMMessages converts session history to LLM messages, preserving tool call context.
func buildLLMMessages(session *AISession) []ai.Message {
	messages := []ai.Message{
		{Role: "system", Content: ai.SystemPrompt},
	}
	for _, entry := range session.History {
		msg := ai.Message{
			Role:    entry.Role,
			Content: entry.Content,
		}
		// Restore tool_calls from history (needed for assistant messages that requested tools)
		if entry.Role == "assistant" && entry.ToolCalls != nil {
			// entry.ToolCalls is interface{}, need to re-serialize then parse
			if raw, err := json.Marshal(entry.ToolCalls); err == nil {
				var tcs []ai.ToolCall
				if json.Unmarshal(raw, &tcs) == nil {
					msg.ToolCalls = tcs
				}
			}
		}
		messages = append(messages, msg)
	}
	return messages
}

func fallbackResponse(userMsg string) string {
	msg := userMsg
	switch {
	case containsKeyword(msg, "plan", "attack", "pentest"):
		return "Generating attack plan. Typical phases: 1) Info Gathering (port scan, env detection) 2) Initial Access (APIServer, Kubelet, Etcd) 3) Execution (pod exec, backdoor) 4) Persistence (SA, CronJob) 5) Privilege Escalation 6) Lateral Movement. Type your objective and I'll create a plan."
	case containsKeyword(msg, "分析", "逃逸", "提权", "dashboard", "面板", "评估", "analyze", "assess"):
		return `【无 LLM 模式 - 基于已收集信息的规则分析】

请按以下步骤手动收集证据后自行判断：

### 1. 提权可行性 (Privilege Escalation)
- 点击 Kubectl 标签页的 **Auth Can-I** 按钮，查看当前凭据权限
- 若有 create serviceaccount + create clusterrolebinding → 可直接创建 cluster-admin
- 若有 get secrets 在全命名空间 → 可窃取 SA token 提权
- 若有 create pods + privileged 容器 → 可部署特权 pod 逃逸

### 2. 逃逸可行性 (Container Escape)
- 在命令执行标签页选择可疑 Pod（privileged / hostPath / hostNetwork），执行：
  cat /proc/1/status | grep CapEff
  ls -la /var/run/docker.sock 2>/dev/null
  mount | grep hostPath
- 若当前 Pod 非特权：点击 Lateral 标签页 **Show Node 污点**，创建污点容忍 Pod 调度到目标节点
- 参考 Escape 标签页查看内核漏洞列表（DirtyPipe / cgroup / DirtyCow）

### 3. Dashboard 可达性
- Kubectl 标签页 **Get Services** → 搜索 "dashboard"
- Access 标签页 **检测Dashboard** → 探测 30443/30000 等端口
- 若有 unauthenticated 访问：直接得 token / login 即可

### 下一步建议
1. 先点 Kubectl 标签页的 **Get Pods / Get Nodes / Auth Can-I / Get CRB** 收集基础信息
2. 再点 **Get Secrets** 看是否有 SA token 泄露
3. 然后到执行标签页选特权 Pod 执行命令判断逃逸条件
4. 配置 LLM API Key 后可使用 AI 自动完成上述分析流程`

	case containsKeyword(msg, "info", "scan", "port", "gather"):
		return "Start with port scan to discover open K8s services (6443, 10250, 2379). Then check APIServer anonymous access. Use the /info endpoints for environment detection and capability decoding."
	case containsKeyword(msg, "access", "apiserver", "kubelet", "etcd"):
		return "Check APIServer on port 6443 first. If no token, try anonymous access. Kubelet on 10250 for pod exec. Etcd on 2379 for direct key access. Use /access endpoints."
	case containsKeyword(msg, "execute", "exec", "shell", "command"):
		return "Use /exec endpoints to list pods and execute commands. Generate backdoor pod YAML with host mounts for privileged access. Check RBAC with auth can-i --list."
	case containsKeyword(msg, "persist", "backdoor", "persistence"):
		return "Create admin ServiceAccount with cluster-admin binding for persistence. Deploy CronJob or DaemonSet backdoors with host mounts. Generate shadow kubeconfig for external access."
	case containsKeyword(msg, "escape", "privileged", "container"):
		return "Check for privileged container mode, host mounts, docker.sock access. Use /escape endpoints for guided escape commands. Kernel exploits: CVE-2022-0847 (DirtyPipe), CVE-2022-0492 (cgroup)."
	case containsKeyword(msg, "lateral", "secret", "service", "network"):
		return "Dump secrets from all namespaces. Discover services and endpoints for internal network mapping. Check network policies for lateral movement paths. Use /lateral endpoints."
	case containsKeyword(msg, "help", "what", "how"):
		return "I am K8sPen AI assistant. I can help with: port scanning, K8s access checks, pod execution, persistence setup, container escape, lateral movement, and kubectl operations. Describe what you want to do."
	default:
		return "I understand you want to probe the target. Start with information gathering - scan ports, check environment, and assess the attack surface. What specific phase would you like to focus on?"
	}
}

func containsKeyword(msg string, keywords ...string) bool {
	lower := msg
	for _, kw := range keywords {
		if len(lower) >= len(kw) {
			for i := 0; i <= len(lower)-len(kw); i++ {
				if lower[i] == kw[0] {
					match := true
					for j := 0; j < len(kw) && match; j++ {
						match = lower[i+j] == kw[j] || (lower[i+j] >= 'A' && lower[i+j] <= 'Z' && lower[i+j]+32 == kw[j]) || (lower[i+j] >= 'a' && lower[i+j] <= 'z' && lower[i+j]-32 == kw[j])
					}
					if match {
						return true
					}
				}
			}
		}
	}
	return false
}

func defaultPlanSteps() []engine.PlanStep {
	return []engine.PlanStep{
		{Phase: engine.PhaseInfo, Tool: "info/port-scan", Action: "scan_k8s_ports", Description: "Scan K8s common ports", Status: "pending"},
		{Phase: engine.PhaseInfo, Tool: "info/evaluate", Action: "run_basic_profile", Description: "Gather environment info", Status: "pending"},
		{Phase: engine.PhaseAccess, Tool: "access/api-server", Action: "check_anonymous", Description: "Check APIServer anonymous access", Status: "pending"},
		{Phase: engine.PhaseAccess, Tool: "access/kubelet", Action: "check_kubelet", Description: "Check Kubelet unauthenticated access", Status: "pending"},
		{Phase: engine.PhaseAccess, Tool: "access/etcd", Action: "check_etcd", Description: "Check Etcd unauthorized access", Status: "pending"},
		{Phase: engine.PhaseExec, Tool: "exec/api-server", Action: "list_pods", Description: "List pods via API", Status: "pending"},
		{Phase: engine.PhaseLateral, Tool: "lateral/secrets", Action: "dump_secrets", Description: "Dump secrets from all namespaces", Status: "pending"},
		{Phase: engine.PhaseLateral, Tool: "lateral/services", Action: "discover_services", Description: "Discover internal services", Status: "pending"},
	}
}

func parsePlanJSON(content string) []engine.PlanStep {
	// Try to find JSON array with "steps" key
	type planResp struct {
		Steps []struct {
			Phase       string `json:"phase"`
			Tool        string `json:"tool"`
			Action      string `json:"action"`
			Description string `json:"description"`
		} `json:"steps"`
	}
	var resp planResp
	if err := json.Unmarshal([]byte(content), &resp); err == nil && len(resp.Steps) > 0 {
		steps := make([]engine.PlanStep, 0, len(resp.Steps))
		for _, s := range resp.Steps {
			var phase engine.AttackPhase
			switch s.Phase {
			case "info":
				phase = engine.PhaseInfo
			case "access":
				phase = engine.PhaseAccess
			case "exec":
				phase = engine.PhaseExec
			case "persist":
				phase = engine.PhasePersist
			case "escape":
				phase = engine.PhaseEscape
			case "lateral":
				phase = engine.PhaseLateral
			case "kubectl":
				phase = engine.PhaseKubectl
			default:
				phase = engine.PhaseInfo
			}
			steps = append(steps, engine.PlanStep{
				Phase:       phase,
				Tool:        s.Tool,
				Action:      s.Action,
				Description: s.Description,
				Status:      "pending",
			})
		}
		return steps
	}
	return nil
}
