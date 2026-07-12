package handler

import (
	"testing"

	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

func TestPlanStepToolCallMapsReadOnlySteps(t *testing.T) {
	call, ok := planStepToolCall(engine.PlanStep{Action: "check_kubelet"})
	if !ok || call.Function.Name != "access_kubelet" {
		t.Fatalf("expected kubelet plan action to map to dispatcher, got %#v ok=%v", call, ok)
	}

	if _, ok := planStepToolCall(engine.PlanStep{Action: "dump_secrets"}); ok {
		t.Fatal("expected sensitive plan action to remain a manual workspace action")
	}
}
