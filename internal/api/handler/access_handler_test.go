package handler

import "testing"

func TestParseKubeconfigContent(t *testing.T) {
	content := `
apiVersion: v1
kind: Config
clusters:
- name: demo-cluster
  cluster:
    server: https://10.0.0.1:6443
contexts:
- name: demo-context
  context:
    cluster: demo-cluster
    user: demo-user
current-context: demo-context
users:
- name: demo-user
  user:
    token: demo-token
`

	parsed, err := parseKubeconfigContent(content)
	if err != nil {
		t.Fatalf("expected kubeconfig to parse, got error: %v", err)
	}
	if len(parsed.Clusters) != 1 || parsed.Clusters[0] != "demo-cluster" {
		t.Fatalf("expected cluster name to be parsed, got %#v", parsed.Clusters)
	}
	if len(parsed.Contexts) != 1 || parsed.Contexts[0] != "demo-context" {
		t.Fatalf("expected context name to be parsed, got %#v", parsed.Contexts)
	}
	if len(parsed.Users) != 1 || parsed.Users[0] != "demo-user" {
		t.Fatalf("expected user name to be parsed, got %#v", parsed.Users)
	}
	if parsed.CurrentContext != "demo-context" {
		t.Fatalf("expected current context demo-context, got %q", parsed.CurrentContext)
	}
	if len(parsed.Servers) != 1 || parsed.Servers[0] != "https://10.0.0.1:6443" {
		t.Fatalf("expected server to be parsed, got %#v", parsed.Servers)
	}
	if len(parsed.TokensFound) != 1 || parsed.TokensFound[0] != "demo-token" {
		t.Fatalf("expected token to be parsed, got %#v", parsed.TokensFound)
	}
}
