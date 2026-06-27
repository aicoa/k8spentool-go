package ai

import (
	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

var Tools = []ToolDefinition{
	// INFO
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "info_port_scan",
			Description: "Scan target for open K8s ports (6443, 10250, 2379, 8080, 10255, 443, 8443)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"host": map[string]interface{}{"type": "string", "description": "Target host IP"},
					"ports": map[string]interface{}{"type": "string", "description": "Ports to scan, comma-separated or range", "default": "6443,10250,2379,8080,10255"},
				},
				"required": []string{"host"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "info_run_evaluate",
			Description: "Run CDK-style container/K8s environment evaluation profile",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string", "description": "Target host"},
					"profile":     map[string]interface{}{"type": "string", "enum": []string{"basic", "extended", "full"}, "default": "basic"},
				},
				"required": []string{"target_host"},
			},
		},
	},
	// ACCESS
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "access_apiserver",
			Description: "Check APIServer access on port 6443 (secure) or 8080 (insecure)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string", "description": "Target host"},
					"token":       map[string]interface{}{"type": "string", "description": "Bearer token if available"},
				},
				"required": []string{"target_host"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "access_kubelet",
			Description: "Check Kubelet unauthenticated access on port 10250",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "access_etcd_check",
			Description: "Check Etcd unauthorized access on port 2379",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "access_dashboard",
			Description: "Check K8s Dashboard unauthenticated access",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"port":        map[string]interface{}{"type": "integer", "default": 30443},
				},
				"required": []string{"target_host"},
			},
		},
	},
	// EXEC
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "exec_list_pods",
			Description: "List all pods via APIServer or Kubelet",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
					"namespace":   map[string]interface{}{"type": "string", "default": ""},
				},
				"required": []string{"target_host"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "exec_command",
			Description: "Execute command in a pod",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"namespace":   map[string]interface{}{"type": "string", "default": "default"},
					"pod_name":    map[string]interface{}{"type": "string"},
					"command":     map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host", "pod_name", "command"},
			},
		},
	},
	// LATERAL
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "lateral_list_secrets",
			Description: "List all secrets in the cluster (requires API access)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host", "token"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "lateral_view_secret",
			Description: "View and decode a specific secret",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"namespace":   map[string]interface{}{"type": "string"},
					"secret_name": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host", "namespace", "secret_name", "token"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "lateral_discover_services",
			Description: "Discover services and endpoints in the cluster",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host", "token"},
			},
		},
	},
	// PERSIST
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "persist_create_admin_sa",
			Description: "Create a high-privilege ServiceAccount with cluster-admin binding (DESTRUCTIVE)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
					"namespace":   map[string]interface{}{"type": "string", "default": "kube-system"},
				},
				"required": []string{"target_host", "token"},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "persist_cronjob",
			Description: "Deploy a CronJob backdoor (DESTRUCTIVE)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
					"lhost":       map[string]interface{}{"type": "string", "description": "Callback host for reverse shell"},
					"lport":       map[string]interface{}{"type": "string", "description": "Callback port"},
				},
				"required": []string{"target_host", "token", "lhost", "lport"},
			},
		},
	},
	// ESCAPE
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "escape_check",
			Description: "Check container escape conditions (privileged, mounts, capabilities, docker.sock)",
			Parameters: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "escape_privileged",
			Description: "Attempt privileged container escape (DESTRUCTIVE)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"pod_name":    map[string]interface{}{"type": "string"},
					"lhost":       map[string]interface{}{"type": "string"},
					"lport":       map[string]interface{}{"type": "string"},
				},
				"required": []string{"target_host", "pod_name", "lhost", "lport"},
			},
		},
	},
	// KUBECTL
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "kubectl_exec",
			Description: "Execute arbitrary kubectl command",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_host": map[string]interface{}{"type": "string"},
					"token":       map[string]interface{}{"type": "string"},
					"command":     map[string]interface{}{"type": "string", "description": "kubectl command without 'kubectl' prefix, e.g. 'get pods -A'"},
				},
				"required": []string{"target_host", "command"},
			},
		},
	},
}

func GetToolByName(name string) *ToolDefinition {
	for _, t := range Tools {
		if t.Function.Name == name {
			return &t
		}
	}
	return nil
}

// GetOpenAIToolDefinitions returns tools in OpenAI function calling format
func GetOpenAIToolDefinitions() []ToolDefinition {
	return Tools
}

// GetToolDefinitionsForPhase returns tools relevant to a specific attack phase
func GetToolDefinitionsForPhase(phase engine.AttackPhase) []ToolDefinition {
	prefix := ""
	switch phase {
	case engine.PhaseInfo:
		prefix = "info_"
	case engine.PhaseAccess:
		prefix = "access_"
	case engine.PhaseExec:
		prefix = "exec_"
	case engine.PhasePersist:
		prefix = "persist_"
	case engine.PhaseEscape:
		prefix = "escape_"
	case engine.PhaseLateral:
		prefix = "lateral_"
	case engine.PhaseKubectl:
		prefix = "kubectl_"
	default:
		return Tools
	}

	var filtered []ToolDefinition
	for _, t := range Tools {
		if len(t.Function.Name) > len(prefix) && t.Function.Name[:len(prefix)] == prefix {
			filtered = append(filtered, t)
		}
	}
	return filtered
}
