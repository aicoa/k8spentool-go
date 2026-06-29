package ai

import (
	"testing"

	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

func TestCheckActionAllowsReadonlyKubectlExec(t *testing.T) {
	cfg := DefaultSafetyConfig()
	guard := cfg.CheckAction("kubectl_exec", `{"command":"get pods -A"}`, engine.RiskHigh)
	if guard.NeedApproval {
		t.Fatalf("readonly kubectl get should not require approval")
	}
}

func TestCheckActionBlocksDestructiveKubectlExec(t *testing.T) {
	cfg := DefaultSafetyConfig()
	guard := cfg.CheckAction("kubectl_exec", `{"command":"delete pod test -n default"}`, engine.RiskHigh)
	if !guard.NeedApproval {
		t.Fatalf("destructive kubectl delete should require approval")
	}
}
