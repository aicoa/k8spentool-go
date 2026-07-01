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
