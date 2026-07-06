package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDispatchReturnsStructuredJSON(t *testing.T) {
	call := ToolCall{
		ID:   "call_1",
		Type: "function",
		Function: FunctionCallArg{
			Name:      "escape_check",
			Arguments: `{}`,
		},
	}

	result := Dispatch(context.Background(), call, &AuthCreds{})
	var payload ToolResultPayload
	if err := json.Unmarshal([]byte(result.Output), &payload); err != nil {
		t.Fatalf("expected structured JSON output, got error: %v", err)
	}
	if payload.Tool != "escape_check" {
		t.Fatalf("expected tool name escape_check, got %q", payload.Tool)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok status, got %q", payload.Status)
	}
	if payload.Summary == "" {
		t.Fatalf("expected non-empty summary")
	}
}

func TestDispatchRejectsLoopbackOverrideForSelectedTarget(t *testing.T) {
	call := ToolCall{
		ID:   "call_2",
		Type: "function",
		Function: FunctionCallArg{
			Name:      "info_port_scan",
			Arguments: `{"host":"127.0.0.1"}`,
		},
	}

	result := Dispatch(context.Background(), call, &AuthCreds{Host: "user-ys.ys100.com"})
	var payload ToolResultPayload
	if err := json.Unmarshal([]byte(result.Output), &payload); err != nil {
		t.Fatalf("expected structured JSON output, got error: %v", err)
	}
	if payload.Status != "error" {
		t.Fatalf("expected error status for loopback override, got %q", payload.Status)
	}
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured data payload, got %T", payload.Data)
	}
	if got, _ := data["execution_location"].(string); got != "backend_process" {
		t.Fatalf("expected backend_process execution_location, got %q", got)
	}
	if got, _ := data["selected_target_host"].(string); got != "user-ys.ys100.com" {
		t.Fatalf("expected selected target host to be preserved, got %q", got)
	}
	if got, _ := data["valid_for_selected_target"].(bool); got {
		t.Fatalf("expected loopback override to be invalid for selected target")
	}
}

func TestDispatchExecCommandRequiresPodName(t *testing.T) {
	call := ToolCall{
		ID:   "call_3",
		Type: "function",
		Function: FunctionCallArg{
			Name:      "exec_command",
			Arguments: `{"namespace":"default","command":"id"}`,
		},
	}

	result := Dispatch(context.Background(), call, &AuthCreds{})
	var payload ToolResultPayload
	if err := json.Unmarshal([]byte(result.Output), &payload); err != nil {
		t.Fatalf("expected structured JSON output, got error: %v", err)
	}
	if payload.Status != "error" {
		t.Fatalf("expected error status for missing pod_name, got %q", payload.Status)
	}
	if !strings.Contains(payload.Summary, "pod_name is required") {
		t.Fatalf("expected pod_name guidance, got %q", payload.Summary)
	}
}

func TestDispatchLateralViewSecretRejectsMissingSecretName(t *testing.T) {
	call := ToolCall{
		ID:   "call_4",
		Type: "function",
		Function: FunctionCallArg{
			Name:      "lateral_view_secret",
			Arguments: `{"namespace":"kube-system"}`,
		},
	}

	result := Dispatch(context.Background(), call, &AuthCreds{})
	var payload ToolResultPayload
	if err := json.Unmarshal([]byte(result.Output), &payload); err != nil {
		t.Fatalf("expected structured JSON output, got error: %v", err)
	}
	if payload.Status != "error" {
		t.Fatalf("expected error status for missing secret_name, got %q", payload.Status)
	}
	if !strings.Contains(payload.Summary, "secret_name is required") {
		t.Fatalf("expected secret_name guidance, got %q", payload.Summary)
	}
}
