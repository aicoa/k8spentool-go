package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trymonoly/K8sPenTool-ng/internal/api/ws"
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

type TargetHandler struct {
	hub      *ws.Hub
	sessions map[string]*engine.SessionState
	storeDir string
	mu       sync.RWMutex
}

func NewTargetHandler(hub *ws.Hub) *TargetHandler {
	h := &TargetHandler{
		hub:      hub,
		sessions: make(map[string]*engine.SessionState),
	}
	h.initPersistence()
	return h
}

func targetStoreDir() string {
	if v := os.Getenv("K8SPEN_TARGETS_DIR"); strings.TrimSpace(v) != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".k8spen/targets"
	}
	return filepath.Join(home, ".k8spen", "targets")
}

func (h *TargetHandler) initPersistence() {
	h.storeDir = targetStoreDir()
	_ = os.MkdirAll(h.storeDir, 0700)

	entries, err := os.ReadDir(h.storeDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(h.storeDir, entry.Name()))
		if readErr != nil {
			continue
		}
		var state engine.SessionState
		if err := json.Unmarshal(body, &state); err != nil {
			continue
		}
		if state.Target == nil || state.Target.ID == "" {
			continue
		}
		if state.PhaseResults == nil {
			state.PhaseResults = make(map[engine.AttackPhase][]engine.StepResult)
		}
		h.sessions[state.Target.ID] = &state
	}
}

func (h *TargetHandler) saveSession(session *engine.SessionState) {
	if session == nil || session.Target == nil || session.Target.ID == "" {
		return
	}
	snapshot := session.Snapshot()
	body, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(h.storeDir, snapshot.Target.ID+".json"), body, 0600)
}

func (h *TargetHandler) deleteSessionFile(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	_ = os.Remove(filepath.Join(h.storeDir, id+".json"))
}

type CreateTargetRequest struct {
	Host       string `json:"host" binding:"required"`
	Port       int    `json:"port"`
	Token      string `json:"token"`
	AuthType   string `json:"auth_type"`
	SkipTLS    bool   `json:"skip_tls"`
	TimeoutSec int    `json:"timeout_sec"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Kubeconfig string `json:"kubeconfig"`
}

func (h *TargetHandler) CreateTarget(c *gin.Context) {
	var req CreateTargetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Port == 0 {
		req.Port = 6443
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
		return
	}
	// Auto-detect auth type from provided credentials
	if req.AuthType == "" {
		if req.Token != "" {
			req.AuthType = "token"
		} else if req.Username != "" || req.Password != "" {
			req.AuthType = "userpass"
		} else {
			req.AuthType = "none"
		}
	}

	h.mu.Lock()

	_, existing := h.findSessionByEndpointLocked(req.Host, req.Port)
	if existing != nil && existing.Target != nil {
		existing.Target.Host = req.Host
		existing.Target.Port = req.Port
		existing.Target.Token = req.Token
		existing.Target.AuthType = engine.AuthType(req.AuthType)
		existing.Target.SkipTLS = req.SkipTLS
		existing.Target.TimeoutSec = req.TimeoutSec
		existing.Target.Username = req.Username
		existing.Target.Password = req.Password
		existing.Target.Kubeconfig = req.Kubeconfig
		if existing.Target.CreatedAt.IsZero() {
			existing.Target.CreatedAt = time.Now()
		}
		h.mu.Unlock()
		h.saveSession(existing)
		c.JSON(http.StatusCreated, existing.Target)
		return
	}

	target := &engine.Target{
		ID:         uuid.New().String(),
		Host:       req.Host,
		Port:       req.Port,
		Token:      req.Token,
		AuthType:   engine.AuthType(req.AuthType),
		SkipTLS:    req.SkipTLS,
		TimeoutSec: req.TimeoutSec,
		Username:   req.Username,
		Password:   req.Password,
		Kubeconfig: req.Kubeconfig,
		CreatedAt:  time.Now(),
	}

	h.sessions[target.ID] = engine.NewSessionState(target)
	created := h.sessions[target.ID]
	h.mu.Unlock()
	h.saveSession(created)

	if h.hub != nil {
		h.hub.Broadcast(&ws.Message{
			Type:     ws.MsgStatus,
			TargetID: target.ID,
			Payload:  gin.H{"status": "created", "host": target.Host},
		})
	}

	c.JSON(http.StatusCreated, target)
}

func (h *TargetHandler) ListTargets(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	targets := make([]*engine.Target, 0, len(h.sessions))
	for _, s := range h.sessions {
		targets = append(targets, s.Target)
	}
	sort.Slice(targets, func(i, j int) bool {
		left := targets[i]
		right := targets[j]
		switch {
		case left == nil && right == nil:
			return false
		case left == nil:
			return false
		case right == nil:
			return true
		case !left.CreatedAt.Equal(right.CreatedAt):
			return left.CreatedAt.After(right.CreatedAt)
		case !strings.EqualFold(left.Host, right.Host):
			return strings.ToLower(left.Host) < strings.ToLower(right.Host)
		default:
			return left.ID < right.ID
		}
	})
	c.JSON(http.StatusOK, targets)
}

func (h *TargetHandler) GetTarget(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	c.JSON(http.StatusOK, session.Target)
}

func (h *TargetHandler) DeleteTarget(c *gin.Context) {
	id := c.Param("id")
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.sessions[id]; !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	delete(h.sessions, id)
	h.deleteSessionFile(id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (h *TargetHandler) GetSession(id string) (*engine.SessionState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[id]
	return s, ok
}

func (h *TargetHandler) RecordStep(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	session, ok := h.sessions[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}

	var req struct {
		Phase     string      `json:"phase" binding:"required"`
		Tool      string      `json:"tool" binding:"required"`
		Action    string      `json:"action" binding:"required"`
		Source    string      `json:"source,omitempty"`
		Success   bool        `json:"success"`
		Summary   string      `json:"summary"`
		Data      interface{} `json:"data,omitempty"`
		Output    string      `json:"output,omitempty"`
		Error     string      `json:"error,omitempty"`
		RiskLevel string      `json:"risk_level,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	phase, ok := parseAttackPhase(req.Phase)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid phase"})
		return
	}

	result := engine.StepResult{
		ID:        uuid.New().String(),
		Phase:     phase,
		Tool:      req.Tool,
		Action:    req.Action,
		Source:    req.Source,
		Success:   req.Success,
		Summary:   req.Summary,
		Data:      req.Data,
		Output:    req.Output,
		RiskLevel: parseRiskLevel(req.RiskLevel),
		Timestamp: time.Now(),
		Error:     req.Error,
	}
	session.AddPhaseResult(result)
	h.saveSession(session)
	c.JSON(http.StatusOK, gin.H{"status": "recorded", "target_id": id, "phase": phase.String()})
}

func (h *TargetHandler) GetHub() *ws.Hub {
	return h.hub
}

// GetProxyConfig returns the current global SOCKS5 proxy configuration.
func (h *TargetHandler) GetProxyConfig(c *gin.Context) {
	cfg := util.GetProxyConfig()
	if cfg == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// SetProxyConfig sets the global SOCKS5 proxy configuration.
func (h *TargetHandler) SetProxyConfig(c *gin.Context) {
	var req util.ProxyConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Host == "" || req.Port == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host and port are required"})
		return
	}
	util.SetProxyConfig(&req)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "proxy": req})
}

// ClearProxyConfig disables and clears the global proxy configuration.
func (h *TargetHandler) ClearProxyConfig(c *gin.Context) {
	util.ClearProxyConfig()
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

func parseAttackPhase(phase string) (engine.AttackPhase, bool) {
	switch phase {
	case "info":
		return engine.PhaseInfo, true
	case "access":
		return engine.PhaseAccess, true
	case "exec":
		return engine.PhaseExec, true
	case "persist":
		return engine.PhasePersist, true
	case "escape":
		return engine.PhaseEscape, true
	case "lateral":
		return engine.PhaseLateral, true
	case "kubectl":
		return engine.PhaseKubectl, true
	default:
		return engine.PhaseSetup, false
	}
}

func parseRiskLevel(level string) engine.RiskLevel {
	switch level {
	case "critical":
		return engine.RiskCritical
	case "high":
		return engine.RiskHigh
	case "medium":
		return engine.RiskMedium
	case "low":
		return engine.RiskLow
	default:
		return engine.RiskInfo
	}
}

func (h *TargetHandler) findSessionByEndpointLocked(host string, port int) (string, *engine.SessionState) {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	for id, session := range h.sessions {
		if session == nil || session.Target == nil {
			continue
		}
		if session.Target.Port != port {
			continue
		}
		if strings.ToLower(strings.TrimSpace(session.Target.Host)) == normalizedHost {
			return id, session
		}
	}
	return "", nil
}
