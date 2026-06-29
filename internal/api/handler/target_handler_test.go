package handler

import (
	"testing"

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
