package handler

import (
	"context"
	"encoding/json"
	"fmt"
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
	ID             string              `json:"id"`
	TargetID       string              `json:"target_id"`
	Target         *engine.Target      `json:"target,omitempty"`
	UIContext      *AISessionUIContext `json:"ui_context,omitempty"`
	Plan           *engine.AttackPlan  `json:"plan,omitempty"`
	Status         string              `json:"status"`
	Messages       []ai.Message        `json:"messages,omitempty"`
	History        []AIHistoryEntry    `json:"history"`
	PendingActions []PendingToolAction `json:"pending_actions,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	Auth           *ai.AuthCreds       `json:"auth"`
	mu             sync.RWMutex
	processing     bool // guard against concurrent Chat requests on the same session
}

type AIHistoryEntry struct {
	Role            string      `json:"role"`
	Content         string      `json:"content"`
	ToolCalls       interface{} `json:"tool_calls,omitempty"`
	ToolCallID      string      `json:"tool_call_id,omitempty"`
	PendingActionID string      `json:"pending_action_id,omitempty"`
	Timestamp       time.Time   `json:"timestamp"`
}

type PendingToolAction struct {
	ID               string      `json:"id"`
	ToolCall         ai.ToolCall `json:"tool_call"`
	AssistantContent string      `json:"assistant_content,omitempty"`
	Status           string      `json:"status"`
	CreatedAt        time.Time   `json:"created_at"`
}

type AISessionPodContext struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Container string `json:"container,omitempty"`
}

type AISessionUIContext struct {
	SelectedPod     *AISessionPodContext `json:"selected_pod,omitempty"`
	SharedPodSource string               `json:"shared_pod_source,omitempty"`
	SharedPodCount  int                  `json:"shared_pod_count,omitempty"`
}

type aiChatClient interface {
	Chat(ctx context.Context, messages []ai.Message, tools []ai.ToolDefinition) (*ai.ChatResponse, error)
}

type AIHandler struct {
	sessions    map[string]*AISession
	mu          sync.RWMutex
	llmClient   aiChatClient
	llmConfig   *ai.LLMConfig
	sessionsDir string
	targetStore aiTargetStore
}

type aiTargetStore interface {
	GetSession(id string) (*engine.SessionState, bool)
}

type aiSessionSummaryResponse struct {
	ID             string              `json:"id"`
	TargetID       string              `json:"target_id"`
	Target         *engine.Target      `json:"target,omitempty"`
	Status         string              `json:"status"`
	PendingActions []PendingToolAction `json:"pending_actions,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	CanResumeChat  bool                `json:"can_resume_chat"`
}

type aiSessionDetailResponse struct {
	ID             string              `json:"id"`
	TargetID       string              `json:"target_id"`
	Target         *engine.Target      `json:"target,omitempty"`
	UIContext      *AISessionUIContext `json:"ui_context,omitempty"`
	Plan           *engine.AttackPlan  `json:"plan,omitempty"`
	Status         string              `json:"status"`
	Messages       []ai.Message        `json:"messages,omitempty"`
	History        []AIHistoryEntry    `json:"history"`
	PendingActions []PendingToolAction `json:"pending_actions,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	CanResumeChat  bool                `json:"can_resume_chat"`
}

func NewAIHandler(targetStore aiTargetStore) *AIHandler {
	h := &AIHandler{
		sessions:    make(map[string]*AISession),
		targetStore: targetStore,
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
			if err != nil {
				continue
			}
			var s AISession
			if err := json.Unmarshal(data, &s); err != nil {
				continue
			}
			s.mu = sync.RWMutex{}
			if len(s.Messages) == 0 && len(s.History) > 0 {
				s.Messages = buildMessagesFromHistory(s.History)
			}
			normalizeSessionStatus(&s)
			h.hydrateSessionAuth(&s)
			h.sessions[s.ID] = &s
		}
	}
	log.Printf("[AI] 已加载 %d 个历史会话", len(h.sessions))
}

func (h *AIHandler) saveSession(session *AISession) {
	// Guard against TOCTOU race with DeleteSession:
	// if the session was deleted from the map, don't resurrect its file.
	h.mu.RLock()
	_, exists := h.sessions[session.ID]
	h.mu.RUnlock()
	if !exists {
		return
	}
	session.mu.RLock()
	data, err := json.Marshal(session)
	session.mu.RUnlock()
	if err != nil {
		return
	}
	path := filepath.Join(h.sessionsDir, session.ID+".json")
	os.WriteFile(path, data, 0600)
}

func (h *AIHandler) deleteSessionFile(id string) {
	path := filepath.Join(h.sessionsDir, id+".json")
	os.Remove(path)
}

func (h *AIHandler) GetOrCreateLLMClient() aiChatClient {
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
		Provider    string `json:"provider"`
		Model       string `json:"model"`
		APIKey      string `json:"api_key"`
		BaseURL     string `json:"base_url"`
		ClearAPIKey bool   `json:"clear_api_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg := ai.LoadConfig()
	if req.Provider != "" {
		cfg.Provider = ai.ProviderType(req.Provider)
	}
	if req.Model != "" {
		cfg.Model = req.Model
	}
	if req.ClearAPIKey {
		cfg.APIKey = ""
	} else if req.APIKey != "" {
		cfg.APIKey = req.APIKey
	}
	if req.BaseURL != "" {
		cfg.BaseURL = req.BaseURL
	}
	if err := ai.SaveConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.mu.Lock()
	h.llmConfig = cfg
	h.llmClient = ai.NewLLMClient(cfg)
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"status": "saved", "provider": string(cfg.Provider), "model": cfg.Model})
}

func (h *AIHandler) CreateSession(c *gin.Context) {
	var req struct {
		TargetID   string              `json:"target_id" binding:"required"`
		Host       string              `json:"host"`
		Token      string              `json:"token"`
		Username   string              `json:"username"`
		Password   string              `json:"password"`
		SkipTLS    bool                `json:"skip_tls"`
		TimeoutSec int                 `json:"timeout_sec"`
		UIContext  *AISessionUIContext `json:"ui_context"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	createdAt := time.Now()
	initialGreeting := buildInitialSessionGreeting(req.Host, req.TargetID, req.UIContext)

	session := &AISession{
		ID:             uuid.New().String(),
		TargetID:       req.TargetID,
		Target:         h.resolveTargetSnapshot(req.TargetID, req.Host, req.Token, req.Username, req.Password, req.SkipTLS, req.TimeoutSec),
		UIContext:      normalizeSessionUIContext(req.UIContext),
		Status:         "active",
		Messages:       []ai.Message{{Role: "assistant", Content: initialGreeting}},
		History:        []AIHistoryEntry{{Role: "assistant", Content: initialGreeting, Timestamp: createdAt}},
		PendingActions: make([]PendingToolAction, 0),
		CreatedAt:      createdAt,
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

	h.hydrateSessionAuth(session)
	h.saveSession(session)
	c.JSON(http.StatusCreated, h.sessionDetailResponse(session))
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
	normalizeSessionStatus(session)
	h.hydrateSessionAuth(session)
	c.JSON(http.StatusOK, h.sessionDetailResponse(session))
}

func (h *AIHandler) ListSessions(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sessions := make([]aiSessionSummaryResponse, 0, len(h.sessions))
	for _, s := range h.sessions {
		normalizeSessionStatus(s)
		h.hydrateSessionAuth(s)
		sessions = append(sessions, h.sessionSummaryResponse(s))
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
	if sessionStopped(session) {
		c.JSON(http.StatusConflict, gin.H{"error": "session is stopped. Please create a new session to continue."})
		return
	}

	// Guard against concurrent Chat requests on the same session.
	session.mu.Lock()
	if session.processing {
		session.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "session is processing another request, please wait"})
		return
	}
	session.processing = true
	session.mu.Unlock()
	defer func() {
		session.mu.Lock()
		session.processing = false
		session.mu.Unlock()
	}()

	var req struct {
		Message string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session.mu.Lock()
	if len(session.PendingActions) > 0 {
		pending := append([]PendingToolAction(nil), session.PendingActions...)
		session.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "pending approval actions exist", "pending_actions": pending})
		return
	}
	userEntry := AIHistoryEntry{
		Role:      "user",
		Content:   req.Message,
		Timestamp: time.Now(),
	}
	session.Messages = append(session.Messages, ai.Message{
		Role:    "user",
		Content: req.Message,
	})
	session.History = append(session.History, AIHistoryEntry{
		Role:      userEntry.Role,
		Content:   userEntry.Content,
		Timestamp: userEntry.Timestamp,
	})
	session.mu.Unlock()

	// ReAct 工具调用循环：LLM 请求工具 → 后端执行 → 结果回灌 → 直到 LLM 给出文本结论
	llm := h.GetOrCreateLLMClient()
	tools := ai.GetOpenAIToolDefinitions()

	if !h.hydrateSessionAuth(session) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session auth credentials not available. Please create a new session."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	outcome, err := h.runToolLoop(ctx, session, tools, llm)

	if err != nil {
		log.Printf("[AI] LLM error: %v, using fallback", err)
		fallback := AIHistoryEntry{
			Role:      "assistant",
			Content:   fallbackResponse(req.Message),
			Timestamp: time.Now(),
		}
		session.mu.Lock()
		session.Messages = append(session.Messages, ai.Message{Role: "assistant", Content: fallback.Content})
		session.History = append(session.History, fallback)
		session.Status = "active"
		session.mu.Unlock()
		h.saveSession(session)
		c.JSON(http.StatusOK, gin.H{
			"session_id":      id,
			"response":        fallback,
			"tool_traces":     []ai.ToolTrace{},
			"pending_actions": session.PendingActions,
		})
		return
	}

	session.mu.Lock()
	session.Messages = stripSystemMessage(outcome.Messages)
	session.History = append(session.History, outcome.HistoryEntries...)
	if outcome.Response.Role != "" {
		session.History = append(session.History, outcome.Response)
	}
	session.PendingActions = outcome.PendingActions
	if len(session.PendingActions) > 0 {
		session.Status = "awaiting_approval"
	} else {
		session.Status = "active"
	}
	session.mu.Unlock()

	h.saveSession(session)

	c.JSON(http.StatusOK, gin.H{
		"session_id":      id,
		"response":        outcome.Response,
		"tool_traces":     outcome.Traces,
		"pending_actions": outcome.PendingActions,
	})
}

type toolLoopOutcome struct {
	Messages       []ai.Message
	HistoryEntries []AIHistoryEntry
	Response       AIHistoryEntry
	Traces         []ai.ToolTrace
	PendingActions []PendingToolAction
}

// runToolLoop 执行 ReAct 循环，最多 maxRounds 轮。
func (h *AIHandler) runToolLoop(ctx context.Context, session *AISession, tools []ai.ToolDefinition, llm aiChatClient) (*toolLoopOutcome, error) {
	const maxRounds = 6

	session.mu.RLock()
	messages := h.buildLLMMessages(session)
	session.mu.RUnlock()

	traces := []ai.ToolTrace{}
	historyEntries := []AIHistoryEntry{}
	pendingActions := append([]PendingToolAction(nil), session.PendingActions...)
	safety := ai.DefaultSafetyConfig()

	for round := 0; round < maxRounds; round++ {
		// Check if session was stopped between Chat() entry and now.
		session.mu.RLock()
		stopped := session.Status == "stopped"
		session.mu.RUnlock()
		if stopped {
			if len(traces) > 0 {
				return &toolLoopOutcome{
					Messages:       messages,
					HistoryEntries: historyEntries,
					Traces:         traces,
					PendingActions: pendingActions,
					Response: AIHistoryEntry{
						Role:      "assistant",
						Content:   summarizeWithTraces("（会话已被停止，以下为已收集到的证据）", traces),
						Timestamp: time.Now(),
					},
				}, nil
			}
			return &toolLoopOutcome{
				Messages:       messages,
				HistoryEntries: historyEntries,
				Traces:         traces,
				PendingActions: pendingActions,
				Response: AIHistoryEntry{
					Role:      "assistant",
					Content:   "会话已被停止。",
					Timestamp: time.Now(),
				},
			}, nil
		}

		resp, err := llm.Chat(ctx, messages, tools)
		if err != nil {
			// 已执行的工具轨迹仍返回给前端
			if len(traces) > 0 {
				return &toolLoopOutcome{
					Messages:       messages,
					HistoryEntries: historyEntries,
					Traces:         traces,
					PendingActions: pendingActions,
					Response: AIHistoryEntry{
						Role:      "assistant",
						Content:   summarizeWithTraces("（LLM 调用出错，以下为已收集到的证据）", traces),
						Timestamp: time.Now(),
					},
				}, nil
			}
			return nil, err
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
			messages = append(messages, ai.Message{
				Role:    "assistant",
				Content: content,
			})
			return &toolLoopOutcome{
				Messages:       messages,
				HistoryEntries: historyEntries,
				Traces:         traces,
				PendingActions: pendingActions,
				Response: AIHistoryEntry{
					Role:      "assistant",
					Content:   content,
					Timestamp: time.Now(),
				},
			}, nil
		}

		// 把 assistant 的 tool_calls 加入消息流
		assistantMsg := ai.Message{
			Role:      "assistant",
			Content:   choice.Message.Content,
			ToolCalls: choice.Message.ToolCalls,
		}
		messages = append(messages, assistantMsg)
		historyEntries = append(historyEntries, AIHistoryEntry{
			Role:      "assistant",
			Content:   choice.Message.Content,
			ToolCalls: choice.Message.ToolCalls,
			Timestamp: time.Now(),
		})

		// 逐个执行工具，结果以 tool 角色回灌
		for _, tc := range choice.Message.ToolCalls {
			// 安全闸门：使用工具的实际风险级别，而非硬编码 RiskHigh
			riskLevel := ai.GetToolRiskLevel(tc.Function.Name)
			guard := safety.CheckAction(tc.Function.Name, tc.Function.Arguments, riskLevel)
			var res ai.DispatchResult
			if guard.NeedApproval {
				res = ai.DispatchResult{
					Output: "需人工批准",
					Trace:  ai.ToolTrace{Tool: tc.Function.Name, Args: tc.Function.Arguments, ResultPreview: "需人工批准", Status: "needs_approval"},
				}
				pendingActions = append(pendingActions, PendingToolAction{
					ID:               uuid.New().String(),
					ToolCall:         tc,
					AssistantContent: choice.Message.Content,
					Status:           "pending",
					CreatedAt:        time.Now(),
				})
			} else {
				res = ai.Dispatch(ctx, tc, session.Auth)
				messages = append(messages, ai.Message{
					Role:       "tool",
					ToolCallID: tc.ID,
					Content:    res.Output,
				})
				historyEntries = append(historyEntries, AIHistoryEntry{
					Role:       "tool",
					Content:    res.Output,
					ToolCallID: tc.ID,
					Timestamp:  time.Now(),
				})
			}
			traces = append(traces, res.Trace)
			log.Printf("[AI] tool %s status=%s risk=%s", tc.Function.Name, res.Trace.Status, riskLevel)
		}

		if len(pendingActions) > 0 {
			return &toolLoopOutcome{
				Messages:       messages,
				HistoryEntries: historyEntries,
				Traces:         traces,
				PendingActions: pendingActions,
				Response: AIHistoryEntry{
					Role:      "assistant",
					Content:   buildPendingApprovalMessage(pendingActions),
					Timestamp: time.Now(),
				},
			}, nil
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
			messages = append(messages, ai.Message{
				Role:    "assistant",
				Content: resp.Choices[0].Message.Content,
			})
			return &toolLoopOutcome{
				Messages:       messages,
				HistoryEntries: historyEntries,
				Traces:         traces,
				PendingActions: pendingActions,
				Response: AIHistoryEntry{
					Role:      "assistant",
					Content:   resp.Choices[0].Message.Content,
					Timestamp: time.Now(),
				},
			}, nil
		}
		return &toolLoopOutcome{
			Messages:       messages,
			HistoryEntries: historyEntries,
			Traces:         traces,
			PendingActions: pendingActions,
			Response: AIHistoryEntry{
				Role:      "assistant",
				Content:   summarizeWithTraces("（达到工具调用轮次上限，以下为已收集证据摘要）", traces),
				Timestamp: time.Now(),
			},
		}, nil
	}
	return &toolLoopOutcome{
		Messages:       messages,
		HistoryEntries: historyEntries,
		Traces:         traces,
		PendingActions: pendingActions,
		Response: AIHistoryEntry{
			Role:      "assistant",
			Content:   "(未触发任何工具调用，也无文本结论)",
			Timestamp: time.Now(),
		},
	}, nil
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
	if sessionStopped(session) {
		c.JSON(http.StatusConflict, gin.H{"error": "session is stopped. Please create a new session to continue."})
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
	if sessionStopped(session) {
		c.JSON(http.StatusConflict, gin.H{"error": "session is stopped. Please create a new session to continue."})
		return
	}

	var req struct {
		StepIndex int    `json:"step_index"`
		ActionID  string `json:"action_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ActionID != "" {
		h.approvePendingAction(c, session, req.ActionID)
		return
	}
	if session.Plan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no plan"})
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if req.StepIndex >= 0 && req.StepIndex < len(session.Plan.Steps) {
		session.Plan.Steps[req.StepIndex].Status = "completed"
		session.Plan.CurrentStep = req.StepIndex + 1
	}

	h.saveSession(session)
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
	session.PendingActions = nil
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
func (h *AIHandler) buildLLMMessages(session *AISession) []ai.Message {
	systemContent := h.buildSystemPrompt(session)
	messages := []ai.Message{{Role: "system", Content: systemContent}}
	if len(session.Messages) > 0 {
		messages = append(messages, session.Messages...)
		return messages
	}
	return append(messages, buildMessagesFromHistory(session.History)...)
}

func buildMessagesFromHistory(history []AIHistoryEntry) []ai.Message {
	messages := make([]ai.Message, 0, len(history))
	for _, entry := range history {
		msg := ai.Message{
			Role:       entry.Role,
			Content:    entry.Content,
			ToolCallID: entry.ToolCallID,
		}
		if entry.Role == "assistant" && entry.ToolCalls != nil {
			if raw, err := json.Marshal(entry.ToolCalls); err == nil {
				var tcs []ai.ToolCall
				if json.Unmarshal(raw, &tcs) == nil {
					msg.ToolCalls = tcs
				}
			}
		}
		if msg.Role == "assistant" || msg.Role == "user" || msg.Role == "tool" {
			messages = append(messages, msg)
		}
	}
	return messages
}

func stripSystemMessage(messages []ai.Message) []ai.Message {
	if len(messages) == 0 {
		return nil
	}
	if messages[0].Role == "system" {
		return append([]ai.Message(nil), messages[1:]...)
	}
	return append([]ai.Message(nil), messages...)
}

func (h *AIHandler) buildSystemPrompt(session *AISession) string {
	target, phase, completedSteps := h.resolvePromptContext(session)
	if target == nil {
		prompt := ai.SystemPrompt
		if uiContextMessage := buildSessionUIContextMessage(session.UIContext); uiContextMessage != "" {
			prompt += "\n\n" + uiContextMessage
		}
		return prompt
	}
	prompt := ai.BuildSystemMessage(target, phase)
	contextMessage := ai.BuildContextMessage(completedSteps)
	if contextMessage != "" {
		prompt += "\n\n" + contextMessage
	}
	if uiContextMessage := buildSessionUIContextMessage(session.UIContext); uiContextMessage != "" {
		prompt += "\n\n" + uiContextMessage
	}
	return prompt
}

func (h *AIHandler) resolvePromptContext(session *AISession) (*engine.Target, engine.AttackPhase, []engine.StepResult) {
	if h.targetStore != nil && session.TargetID != "" {
		if state, ok := h.targetStore.GetSession(session.TargetID); ok && state != nil && state.Target != nil {
			return cloneTarget(state.Target), state.GetPhase(), state.GetResults()
		}
	}
	if session.Target != nil {
		return cloneTarget(session.Target), engine.PhaseSetup, nil
	}
	return nil, engine.PhaseSetup, nil
}

func (h *AIHandler) resolveTargetSnapshot(targetID, host, token, username, password string, skipTLS bool, timeoutSec int) *engine.Target {
	if h.targetStore != nil && targetID != "" {
		if state, ok := h.targetStore.GetSession(targetID); ok && state != nil && state.Target != nil {
			return cloneTarget(state.Target)
		}
	}
	if timeoutSec == 0 {
		timeoutSec = 10
	}
	authType := engine.AuthNone
	switch {
	case token != "":
		authType = engine.AuthToken
	case username != "" || password != "":
		authType = "userpass"
	}
	if host == "" {
		host = targetID
	}
	if host == "" {
		return nil
	}
	return &engine.Target{
		ID:         targetID,
		Host:       host,
		Port:       6443,
		Token:      token,
		AuthType:   authType,
		SkipTLS:    skipTLS,
		TimeoutSec: timeoutSec,
		Username:   username,
		Password:   password,
	}
}

func (h *AIHandler) hydrateSessionAuth(session *AISession) bool {
	if session == nil {
		return false
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if authHasHost(session.Auth) {
		return true
	}
	if auth := authFromTarget(session.Target); auth != nil {
		session.Auth = auth
		return true
	}
	if h.targetStore != nil && session.TargetID != "" {
		if state, ok := h.targetStore.GetSession(session.TargetID); ok && state != nil && state.Target != nil {
			if session.Target == nil {
				session.Target = cloneTarget(state.Target)
			}
			if auth := authFromTarget(state.Target); auth != nil {
				session.Auth = auth
				return true
			}
		}
	}
	return false
}

func authHasHost(auth *ai.AuthCreds) bool {
	return auth != nil && strings.TrimSpace(auth.Host) != ""
}

func normalizeSessionStatus(session *AISession) string {
	if session == nil {
		return ""
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	switch session.Status {
	case "", "created":
		switch {
		case len(session.PendingActions) > 0:
			session.Status = "awaiting_approval"
		case session.Plan != nil:
			session.Status = "planning"
		default:
			session.Status = "active"
		}
	}
	return session.Status
}

func authFromTarget(target *engine.Target) *ai.AuthCreds {
	if target == nil || strings.TrimSpace(target.Host) == "" {
		return nil
	}
	return &ai.AuthCreds{
		Host:       target.Host,
		Token:      target.Token,
		Username:   target.Username,
		Password:   target.Password,
		SkipTLS:    target.SkipTLS,
		TimeoutSec: target.TimeoutSec,
	}
}

func cloneTarget(target *engine.Target) *engine.Target {
	if target == nil {
		return nil
	}
	cloned := *target
	return &cloned
}

func sanitizeTarget(target *engine.Target) *engine.Target {
	if target == nil {
		return nil
	}
	safe := cloneTarget(target)
	safe.Token = ""
	safe.Password = ""
	safe.Kubeconfig = ""
	return safe
}

func (h *AIHandler) sessionSummaryResponse(session *AISession) aiSessionSummaryResponse {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return aiSessionSummaryResponse{
		ID:             session.ID,
		TargetID:       session.TargetID,
		Target:         sanitizeTarget(session.Target),
		Status:         session.Status,
		PendingActions: append([]PendingToolAction(nil), session.PendingActions...),
		CreatedAt:      session.CreatedAt,
		CanResumeChat:  authHasHost(session.Auth),
	}
}

func (h *AIHandler) sessionDetailResponse(session *AISession) aiSessionDetailResponse {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return aiSessionDetailResponse{
		ID:             session.ID,
		TargetID:       session.TargetID,
		Target:         sanitizeTarget(session.Target),
		UIContext:      cloneSessionUIContext(session.UIContext),
		Plan:           session.Plan,
		Status:         session.Status,
		Messages:       append([]ai.Message(nil), session.Messages...),
		History:        append([]AIHistoryEntry(nil), session.History...),
		PendingActions: append([]PendingToolAction(nil), session.PendingActions...),
		CreatedAt:      session.CreatedAt,
		CanResumeChat:  authHasHost(session.Auth),
	}
}

func sessionStopped(session *AISession) bool {
	if session == nil {
		return false
	}
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.Status == "stopped"
}

func buildInitialSessionGreeting(host, targetID string, uiContext *AISessionUIContext) string {
	targetLabel := strings.TrimSpace(host)
	if targetLabel == "" {
		targetLabel = strings.TrimSpace(targetID)
	}
	if targetLabel == "" {
		targetLabel = "current target"
	}

	message := "AI session created for target " + targetLabel + ". I can help plan and execute penetration testing steps. Type \"plan\" to generate an attack plan, or describe your goal (e.g. \"分析这个集群能否逃逸/提权/打Dashboard\")."
	if uiContext == nil || uiContext.SelectedPod == nil || strings.TrimSpace(uiContext.SelectedPod.Name) == "" {
		return message
	}

	namespace := strings.TrimSpace(uiContext.SelectedPod.Namespace)
	if namespace == "" {
		namespace = "default"
	}
	message += "\n\nCurrent UI pod context: " + namespace + "/" + strings.TrimSpace(uiContext.SelectedPod.Name)
	if container := strings.TrimSpace(uiContext.SelectedPod.Container); container != "" {
		message += " (container: " + container + ")"
	}
	return message
}

func normalizeSessionUIContext(uiContext *AISessionUIContext) *AISessionUIContext {
	if uiContext == nil {
		return nil
	}
	normalized := &AISessionUIContext{
		SharedPodSource: strings.TrimSpace(uiContext.SharedPodSource),
		SharedPodCount:  uiContext.SharedPodCount,
	}
	if normalized.SharedPodCount < 0 {
		normalized.SharedPodCount = 0
	}
	if uiContext.SelectedPod != nil {
		name := strings.TrimSpace(uiContext.SelectedPod.Name)
		if name != "" {
			namespace := strings.TrimSpace(uiContext.SelectedPod.Namespace)
			if namespace == "" {
				namespace = "default"
			}
			normalized.SelectedPod = &AISessionPodContext{
				Namespace: namespace,
				Name:      name,
				Container: strings.TrimSpace(uiContext.SelectedPod.Container),
			}
		}
	}
	if normalized.SelectedPod == nil && normalized.SharedPodSource == "" && normalized.SharedPodCount == 0 {
		return nil
	}
	return normalized
}

func cloneSessionUIContext(uiContext *AISessionUIContext) *AISessionUIContext {
	if uiContext == nil {
		return nil
	}
	cloned := &AISessionUIContext{
		SharedPodSource: uiContext.SharedPodSource,
		SharedPodCount:  uiContext.SharedPodCount,
	}
	if uiContext.SelectedPod != nil {
		pod := *uiContext.SelectedPod
		cloned.SelectedPod = &pod
	}
	return cloned
}

func buildSessionUIContextMessage(uiContext *AISessionUIContext) string {
	normalized := normalizeSessionUIContext(uiContext)
	if normalized == nil {
		return ""
	}

	parts := []string{"Current UI context from the web console:"}
	if normalized.SelectedPod != nil {
		selectedPod := normalized.SelectedPod.Namespace + "/" + normalized.SelectedPod.Name
		if normalized.SelectedPod.Container != "" {
			selectedPod += " (container: " + normalized.SelectedPod.Container + ")"
		}
		parts = append(parts, "- selected pod: "+selectedPod)
	}
	if normalized.SharedPodCount > 0 {
		line := fmt.Sprintf("- shared pod cache: %d pod(s)", normalized.SharedPodCount)
		if normalized.SharedPodSource != "" {
			line += " from " + normalized.SharedPodSource
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, "\n")
}

func buildPendingApprovalMessage(actions []PendingToolAction) string {
	pending := make([]PendingToolAction, 0, len(actions))
	for _, action := range actions {
		if action.Status == "pending" {
			pending = append(pending, action)
		}
	}
	if len(pending) == 0 {
		return "没有待批准动作。"
	}
	var sb strings.Builder
	sb.WriteString("以下工具调用需要人工批准后才能继续：\n")
	for _, action := range pending {
		sb.WriteString("- " + action.ToolCall.Function.Name + " [" + action.ID + "]\n")
	}
	sb.WriteString("批准后系统会继续执行并让 LLM 收尾。")
	return sb.String()
}

func (h *AIHandler) approvePendingAction(c *gin.Context, session *AISession, actionID string) {
	if sessionStopped(session) {
		c.JSON(http.StatusConflict, gin.H{"error": "session is stopped. Please create a new session to continue."})
		return
	}
	if !h.hydrateSessionAuth(session) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session auth credentials not available. Please create a new session."})
		return
	}
	session.mu.Lock()
	idx := -1
	var action PendingToolAction
	for i, pending := range session.PendingActions {
		if pending.ID == actionID {
			idx = i
			action = pending
			break
		}
	}
	if idx == -1 {
		session.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "pending action not found"})
		return
	}
	session.PendingActions = append(session.PendingActions[:idx], session.PendingActions[idx+1:]...)
	res := ai.Dispatch(c.Request.Context(), action.ToolCall, session.Auth)
	session.Messages = append(session.Messages, ai.Message{
		Role:       "tool",
		ToolCallID: action.ToolCall.ID,
		Content:    res.Output,
	})
	toolEntry := AIHistoryEntry{
		Role:            "tool",
		Content:         res.Output,
		ToolCallID:      action.ToolCall.ID,
		PendingActionID: action.ID,
		Timestamp:       time.Now(),
	}
	session.History = append(session.History, toolEntry)
	remainingPending := append([]PendingToolAction(nil), session.PendingActions...)
	session.mu.Unlock()

	traces := []ai.ToolTrace{res.Trace}
	if len(remainingPending) > 0 {
		msg := AIHistoryEntry{
			Role:      "assistant",
			Content:   buildPendingApprovalMessage(remainingPending),
			Timestamp: time.Now(),
		}
		session.mu.Lock()
		session.History = append(session.History, msg)
		session.Status = "awaiting_approval"
		session.mu.Unlock()
		h.saveSession(session)
		c.JSON(http.StatusOK, gin.H{
			"response":        msg,
			"tool_traces":     traces,
			"pending_actions": remainingPending,
		})
		return
	}

	llm := h.GetOrCreateLLMClient()
	tools := ai.GetOpenAIToolDefinitions()
	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	outcome, err := h.runToolLoop(ctx, session, tools, llm)
	if err != nil {
		log.Printf("[AI] approve action continue error: %v", err)
		outcome = &toolLoopOutcome{
			Messages:       h.buildLLMMessages(session),
			HistoryEntries: nil,
			Traces:         traces,
			PendingActions: nil,
			Response: AIHistoryEntry{
				Role:      "assistant",
				Content:   "工具已执行，但 LLM 收尾失败。请继续提问查看结果。",
				Timestamp: time.Now(),
			},
		}
	}

	session.mu.Lock()
	session.Messages = stripSystemMessage(outcome.Messages)
	session.History = append(session.History, outcome.HistoryEntries...)
	session.History = append(session.History, outcome.Response)
	session.PendingActions = outcome.PendingActions
	if len(session.PendingActions) > 0 {
		session.Status = "awaiting_approval"
	} else {
		session.Status = "active"
	}
	session.mu.Unlock()

	allTraces := append(traces, outcome.Traces...)
	h.saveSession(session)
	c.JSON(http.StatusOK, gin.H{
		"response":        outcome.Response,
		"tool_traces":     allTraces,
		"pending_actions": outcome.PendingActions,
	})
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
- Dashboard 标签页 **探测 Dashboard 可访问性** → 探测 30443/30000 等端口
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
