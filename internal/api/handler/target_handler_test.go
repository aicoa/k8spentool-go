package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

func TestParseAttackPhase(t *testing.T) {
	phase, ok := parseAttackPhase("exec")
	if !ok || phase != engine.PhaseExec {
		t.Fatalf("expected exec phase, got %v ok=%v", phase, ok)
	}
	if _, ok := parseAttackPhase("unknown"); ok {
		t.Fatalf("expected invalid phase to fail")
	}
}

func TestParseRiskLevel(t *testing.T) {
	if got := parseRiskLevel("high"); got != engine.RiskHigh {
		t.Fatalf("expected high risk, got %v", got)
	}
	if got := parseRiskLevel(""); got != engine.RiskInfo {
		t.Fatalf("expected default info risk, got %v", got)
	}
}

func TestTargetHandlerPersistsSessions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("K8SPEN_TARGETS_DIR", dir)

	h := NewTargetHandler(nil)
	session := engine.NewSessionState(&engine.Target{
		ID:         "target-1",
		Host:       "10.0.0.1",
		Port:       6443,
		AuthType:   engine.AuthToken,
		SkipTLS:    true,
		TimeoutSec: 10,
	})
	session.AddPhaseResult(engine.StepResult{
		ID:        "step-1",
		Phase:     engine.PhaseAccess,
		Tool:      "access",
		Action:    "API server check",
		Success:   true,
		Summary:   "anonymous access works",
		Timestamp: time.Now(),
	})

	h.saveSession(session)

	reloaded := NewTargetHandler(nil)
	got, ok := reloaded.GetSession("target-1")
	if !ok || got == nil {
		t.Fatalf("expected persisted target session to reload")
	}
	if got.Target == nil || got.Target.Host != "10.0.0.1" {
		t.Fatalf("expected target host to persist, got %#v", got.Target)
	}
	if len(got.GetResults()) != 1 {
		t.Fatalf("expected one persisted step result, got %d", len(got.GetResults()))
	}
}

func TestCreateTargetUpsertsExistingEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	t.Setenv("K8SPEN_TARGETS_DIR", dir)

	handler := NewTargetHandler(nil)
	router := gin.New()
	router.POST("/targets", handler.CreateTarget)

	firstReq := httptest.NewRequest(http.MethodPost, "/targets", strings.NewReader(`{"host":"demo.local","username":"alice","password":"pw","skip_tls":true}`))
	firstReq.Header.Set("Content-Type", "application/json")
	firstRec := httptest.NewRecorder()
	router.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusCreated {
		t.Fatalf("expected first create to succeed, got %d body=%s", firstRec.Code, firstRec.Body.String())
	}

	var firstTarget engine.Target
	if err := json.Unmarshal(firstRec.Body.Bytes(), &firstTarget); err != nil {
		t.Fatalf("expected first response to unmarshal: %v", err)
	}
	if firstTarget.ID == "" {
		t.Fatalf("expected first target id to be set")
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/targets", strings.NewReader(`{"host":" demo.local ","token":"new-token","skip_tls":false,"timeout_sec":25}`))
	secondReq.Header.Set("Content-Type", "application/json")
	secondRec := httptest.NewRecorder()
	router.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusCreated {
		t.Fatalf("expected second create to succeed, got %d body=%s", secondRec.Code, secondRec.Body.String())
	}

	var secondTarget engine.Target
	if err := json.Unmarshal(secondRec.Body.Bytes(), &secondTarget); err != nil {
		t.Fatalf("expected second response to unmarshal: %v", err)
	}
	if secondTarget.ID != firstTarget.ID {
		t.Fatalf("expected repeated endpoint create to reuse target id %q, got %q", firstTarget.ID, secondTarget.ID)
	}
	if secondTarget.Token != "new-token" || secondTarget.AuthType != engine.AuthToken {
		t.Fatalf("expected target credentials to be updated, got %#v", secondTarget)
	}
	if secondTarget.SkipTLS {
		t.Fatalf("expected skip tls to update to false")
	}
	if secondTarget.TimeoutSec != 25 {
		t.Fatalf("expected timeout to update to 25, got %d", secondTarget.TimeoutSec)
	}
	if len(handler.sessions) != 1 {
		t.Fatalf("expected one target session after upsert, got %d", len(handler.sessions))
	}
}

func TestListTargetsReturnsNewestFirst(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	t.Setenv("K8SPEN_TARGETS_DIR", dir)

	handler := NewTargetHandler(nil)
	older := engine.NewSessionState(&engine.Target{
		ID:        "target-1",
		Host:      "old.local",
		Port:      6443,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})
	newer := engine.NewSessionState(&engine.Target{
		ID:        "target-2",
		Host:      "new.local",
		Port:      6443,
		CreatedAt: time.Now(),
	})
	handler.sessions["target-1"] = older
	handler.sessions["target-2"] = newer

	router := gin.New()
	router.GET("/targets", handler.ListTargets)

	req := httptest.NewRequest(http.MethodGet, "/targets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected list targets to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	var targets []engine.Target
	if err := json.Unmarshal(rec.Body.Bytes(), &targets); err != nil {
		t.Fatalf("expected targets response to unmarshal: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].ID != "target-2" {
		t.Fatalf("expected newest target first, got %#v", targets)
	}
}
