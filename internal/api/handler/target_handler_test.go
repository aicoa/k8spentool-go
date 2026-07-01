package handler

import (
	"testing"
	"time"

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
