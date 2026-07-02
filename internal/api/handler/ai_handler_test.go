package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/ai"
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

type stubAITargetStore struct {
	session *engine.SessionState
}

func (s stubAITargetStore) GetSession(id string) (*engine.SessionState, bool) {
	if s.session == nil || s.session.Target == nil || s.session.Target.ID != id {
		return nil, false
	}
	return s.session, true
}

func TestBuildMessagesFromHistoryPreservesToolContext(t *testing.T) {
	history := []AIHistoryEntry{
		{
			Role:    "assistant",
			Content: "checking cluster",
			ToolCalls: []ai.ToolCall{{
				ID:   "call_1",
				Type: "function",
				Function: ai.FunctionCallArg{
					Name:      "info_port_scan",
					Arguments: `{"host":"127.0.0.1"}`,
				},
			}},
			Timestamp: time.Now(),
		},
		{
			Role:       "tool",
			Content:    "6443/open",
			ToolCallID: "call_1",
			Timestamp:  time.Now(),
		},
	}

	messages := buildMessagesFromHistory(history)
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
	if len(messages[0].ToolCalls) != 1 {
		t.Fatalf("expected assistant tool call to be preserved")
	}
	if messages[1].ToolCallID != "call_1" {
		t.Fatalf("expected tool_call_id to be preserved, got %q", messages[1].ToolCallID)
	}
}

func TestBuildSystemPromptUsesTargetContext(t *testing.T) {
	handler := NewAIHandler(nil)
	session := &AISession{
		TargetID: "target-1",
		Target: &engine.Target{
			ID:         "target-1",
			Host:       "10.0.0.1",
			Port:       6443,
			AuthType:   engine.AuthToken,
			SkipTLS:    true,
			TimeoutSec: 10,
		},
	}

	prompt := handler.buildSystemPrompt(session)
	if !strings.Contains(prompt, "Current target: 10.0.0.1") {
		t.Fatalf("expected prompt to include target host, got %q", prompt)
	}
	if !strings.Contains(prompt, "Auth type: token") {
		t.Fatalf("expected prompt to include auth type, got %q", prompt)
	}
}

func TestBuildSystemPromptIncludesUIContext(t *testing.T) {
	handler := NewAIHandler(nil)
	session := &AISession{
		Target: &engine.Target{
			ID:         "target-1",
			Host:       "10.0.0.1",
			Port:       6443,
			AuthType:   engine.AuthToken,
			SkipTLS:    true,
			TimeoutSec: 10,
		},
		UIContext: &AISessionUIContext{
			SelectedPod: &AISessionPodContext{
				Namespace: "default",
				Name:      "audit-conf",
				Container: "main",
			},
			SharedPodSource: "kubectl",
			SharedPodCount:  452,
		},
	}

	prompt := handler.buildSystemPrompt(session)
	for _, needle := range []string{
		"selected pod: default/audit-conf (container: main)",
		"shared pod cache: 452 pod(s) from kubectl",
	} {
		if !strings.Contains(prompt, needle) {
			t.Fatalf("expected prompt to include %q, got %q", needle, prompt)
		}
	}
}

func TestUpdateConfigCanClearAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HOME", t.TempDir())

	router := gin.New()
	handler := NewAIHandler(nil)
	router.PUT("/ai/config", handler.UpdateConfig)

	saveReq := httptest.NewRequest(http.MethodPut, "/ai/config", strings.NewReader(`{"provider":"openai","api_key":"secret-value"}`))
	saveReq.Header.Set("Content-Type", "application/json")
	saveRec := httptest.NewRecorder()
	router.ServeHTTP(saveRec, saveReq)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("expected initial save to succeed, got %d", saveRec.Code)
	}

	clearReq := httptest.NewRequest(http.MethodPut, "/ai/config", strings.NewReader(`{"clear_api_key":true}`))
	clearReq.Header.Set("Content-Type", "application/json")
	clearRec := httptest.NewRecorder()
	router.ServeHTTP(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("expected clear request to succeed, got %d", clearRec.Code)
	}

	cfg := ai.LoadConfig()
	if cfg.APIKey != "" {
		t.Fatalf("expected API key to be cleared, got %q", cfg.APIKey)
	}
	body, err := os.ReadFile(ai.ConfigFilePath())
	if err != nil {
		t.Fatalf("expected config file to remain readable: %v", err)
	}
	if strings.Contains(string(body), "secret-value") {
		t.Fatalf("expected cleared config file to stop containing the previous API key")
	}
}

func TestHydrateSessionAuthFromTarget(t *testing.T) {
	handler := NewAIHandler(nil)
	session := &AISession{
		ID:       "session-1",
		TargetID: "target-1",
		Target: &engine.Target{
			ID:         "target-1",
			Host:       "demo.local",
			Token:      "demo-token",
			SkipTLS:    true,
			TimeoutSec: 12,
		},
	}

	if !handler.hydrateSessionAuth(session) {
		t.Fatalf("expected auth hydration to succeed")
	}
	if session.Auth == nil || session.Auth.Host != "demo.local" || session.Auth.Token != "demo-token" {
		t.Fatalf("expected hydrated auth from target, got %#v", session.Auth)
	}
}

func TestSessionResponsesSanitizeSensitiveFields(t *testing.T) {
	handler := NewAIHandler(nil)
	session := &AISession{
		ID:       "session-1",
		TargetID: "target-1",
		Target: &engine.Target{
			ID:         "target-1",
			Host:       "demo.local",
			Token:      "secret-token",
			Username:   "alice",
			Password:   "secret-pass",
			Kubeconfig: "secret-config",
		},
		Auth: &ai.AuthCreds{Host: "demo.local"},
	}

	summary := handler.sessionSummaryResponse(session)
	if summary.Target == nil {
		t.Fatalf("expected sanitized target in summary response")
	}
	if summary.Target.Token != "" || summary.Target.Password != "" || summary.Target.Kubeconfig != "" {
		t.Fatalf("expected sensitive fields to be stripped from summary target, got %#v", summary.Target)
	}

	detail := handler.sessionDetailResponse(session)
	if detail.Target == nil {
		t.Fatalf("expected sanitized target in detail response")
	}
	if detail.Target.Token != "" || detail.Target.Password != "" || detail.Target.Kubeconfig != "" {
		t.Fatalf("expected sensitive fields to be stripped from detail target, got %#v", detail.Target)
	}
}

func TestHydrateSessionAuthFallsBackToTargetStore(t *testing.T) {
	target := &engine.Target{
		ID:         "target-1",
		Host:       "cluster.local",
		Username:   "bob",
		Password:   "pw",
		SkipTLS:    true,
		TimeoutSec: 10,
	}
	handler := NewAIHandler(stubAITargetStore{
		session: engine.NewSessionState(target),
	})
	session := &AISession{ID: "session-1", TargetID: "target-1"}

	if !handler.hydrateSessionAuth(session) {
		t.Fatalf("expected hydration via target store to succeed")
	}
	if session.Auth == nil || session.Auth.Host != "cluster.local" || session.Auth.Username != "bob" {
		t.Fatalf("expected auth to hydrate from target store, got %#v", session.Auth)
	}
	if session.Target == nil || session.Target.Host != "cluster.local" {
		t.Fatalf("expected target snapshot to hydrate from target store, got %#v", session.Target)
	}
}

func TestStoppedSessionRejectsChat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HOME", t.TempDir())

	handler := NewAIHandler(nil)
	handler.sessions["session-1"] = &AISession{
		ID:        "session-1",
		Status:    "stopped",
		CreatedAt: time.Now(),
		Auth:      &ai.AuthCreds{Host: "demo.local"},
	}

	router := gin.New()
	router.POST("/ai/sessions/:id/chat", handler.Chat)

	req := httptest.NewRequest(http.MethodPost, "/ai/sessions/session-1/chat", strings.NewReader(`{"message":"plan"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected stopped session chat to be rejected with 409, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "stopped") {
		t.Fatalf("expected stopped-session error message, got %q", rec.Body.String())
	}
}

func TestCreateSessionPersistsInitialGreetingAndUIContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HOME", t.TempDir())

	handler := NewAIHandler(nil)
	router := gin.New()
	router.POST("/ai/sessions", handler.CreateSession)

	req := httptest.NewRequest(http.MethodPost, "/ai/sessions", strings.NewReader(`{
		"target_id":"target-1",
		"host":"demo.local",
		"username":"alice",
		"password":"secret",
		"skip_tls":true,
		"timeout_sec":10,
		"ui_context":{
			"selected_pod":{"namespace":"default","name":"audit-conf","container":"main"},
			"shared_pod_source":"kubectl",
			"shared_pod_count":452
		}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected session create to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(handler.sessions) != 1 {
		t.Fatalf("expected one session to be stored, got %d", len(handler.sessions))
	}
	var session *AISession
	for _, stored := range handler.sessions {
		session = stored
	}
	if session == nil {
		t.Fatalf("expected stored session")
	}
	if session.UIContext == nil || session.UIContext.SelectedPod == nil {
		t.Fatalf("expected UI context to be persisted, got %#v", session.UIContext)
	}
	if got := session.UIContext.SelectedPod.Name; got != "audit-conf" {
		t.Fatalf("expected selected pod name to persist, got %q", got)
	}
	if len(session.History) != 1 || session.History[0].Role != "assistant" {
		t.Fatalf("expected initial assistant greeting in history, got %#v", session.History)
	}
	if !strings.Contains(session.History[0].Content, "Current UI pod context: default/audit-conf") {
		t.Fatalf("expected greeting to mention selected pod, got %q", session.History[0].Content)
	}
	if len(session.Messages) != 1 || session.Messages[0].Role != "assistant" {
		t.Fatalf("expected initial assistant greeting in messages, got %#v", session.Messages)
	}
}

func TestNormalizeSessionStatusPromotesLegacyCreatedSessions(t *testing.T) {
	session := &AISession{Status: "created"}
	if got := normalizeSessionStatus(session); got != "active" {
		t.Fatalf("expected legacy created session to normalize to active, got %q", got)
	}

	sessionWithPlan := &AISession{Status: "created", Plan: &engine.AttackPlan{ID: "plan-1"}}
	if got := normalizeSessionStatus(sessionWithPlan); got != "planning" {
		t.Fatalf("expected created session with plan to normalize to planning, got %q", got)
	}

	sessionWithPending := &AISession{Status: "created", PendingActions: []PendingToolAction{{ID: "action-1"}}}
	if got := normalizeSessionStatus(sessionWithPending); got != "awaiting_approval" {
		t.Fatalf("expected created session with pending actions to normalize to awaiting_approval, got %q", got)
	}
}
