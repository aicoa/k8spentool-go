package handler

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trymonoly/K8sPenTool-ng/internal/api/ws"
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

type TargetHandler struct {
	hub      *ws.Hub
	sessions map[string]*engine.SessionState
	mu       sync.RWMutex
}

func NewTargetHandler(hub *ws.Hub) *TargetHandler {
	return &TargetHandler{
		hub:      hub,
		sessions: make(map[string]*engine.SessionState),
	}
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
	}

	h.mu.Lock()
	h.sessions[target.ID] = engine.NewSessionState(target)
	h.mu.Unlock()

	h.hub.Broadcast(&ws.Message{
		Type:     ws.MsgStatus,
		TargetID: target.ID,
		Payload:  gin.H{"status": "created", "host": target.Host},
	})

	c.JSON(http.StatusCreated, target)
}

func (h *TargetHandler) ListTargets(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	targets := make([]*engine.Target, 0, len(h.sessions))
	for _, s := range h.sessions {
		targets = append(targets, s.Target)
	}
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
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (h *TargetHandler) GetSession(id string) (*engine.SessionState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[id]
	return s, ok
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
