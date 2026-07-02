package ai

import "testing"

func requiredFields(t *testing.T, toolName string) []string {
	t.Helper()
	tool := GetToolByName(toolName)
	if tool == nil {
		t.Fatalf("tool %q not found", toolName)
	}
	raw, ok := tool.Function.Parameters["required"]
	if !ok {
		return nil
	}
	items, ok := raw.([]string)
	if ok {
		return items
	}
	interfaces, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("tool %q required has unexpected type %T", toolName, raw)
	}
	out := make([]string, 0, len(interfaces))
	for _, item := range interfaces {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("tool %q required item has unexpected type %T", toolName, item)
		}
		out = append(out, text)
	}
	return out
}

func hasField(required []string, field string) bool {
	for _, item := range required {
		if item == field {
			return true
		}
	}
	return false
}

func TestSessionBoundToolsDoNotRequireTargetOrToken(t *testing.T) {
	sessionBoundTools := []string{
		"access_apiserver",
		"access_kubelet",
		"exec_list_pods",
		"lateral_list_secrets",
		"lateral_discover_services",
		"persist_create_admin_sa",
		"persist_cronjob",
		"kubectl_exec",
	}

	for _, toolName := range sessionBoundTools {
		required := requiredFields(t, toolName)
		if hasField(required, "target_host") {
			t.Fatalf("tool %q should not require target_host for session-bound execution", toolName)
		}
		if hasField(required, "token") {
			t.Fatalf("tool %q should not require token for session-bound execution", toolName)
		}
	}
}

func TestExecCommandSchemaIncludesContainerNameAndSessionDefaults(t *testing.T) {
	tool := GetToolByName("exec_command")
	if tool == nil {
		t.Fatal("exec_command tool not found")
	}
	properties, ok := tool.Function.Parameters["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("exec_command properties has unexpected type %T", tool.Function.Parameters["properties"])
	}
	if _, ok := properties["container_name"]; !ok {
		t.Fatal("exec_command should expose optional container_name for multi-container pods")
	}
	required := requiredFields(t, "exec_command")
	if hasField(required, "target_host") || hasField(required, "token") {
		t.Fatalf("exec_command should rely on session host/token defaults, got required=%v", required)
	}
}

func TestAccessKubeletSchemaAllowsOptionalToken(t *testing.T) {
	tool := GetToolByName("access_kubelet")
	if tool == nil {
		t.Fatal("access_kubelet tool not found")
	}
	properties, ok := tool.Function.Parameters["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("access_kubelet properties has unexpected type %T", tool.Function.Parameters["properties"])
	}
	if _, ok := properties["token"]; !ok {
		t.Fatal("access_kubelet should expose optional token for authenticated kubelet checks")
	}
}
