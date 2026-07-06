package handler

import (
	"testing"
)

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

func TestTryParseItemsSecretListOnlyReturnsKeyNames(t *testing.T) {
	body := []byte(`{
		"kind":"SecretList",
		"items":[
			{
				"metadata":{"name":"demo-secret","namespace":"default"},
				"type":"Opaque",
				"data":{"username":"YWRtaW4=","password":"YWRtaW4="}
			}
		]
	}`)

	key, items := tryParseItems(body)
	if key != "secrets" {
		t.Fatalf("expected schema key secrets, got %q", key)
	}
	if len(items) != 1 {
		t.Fatalf("expected one parsed item, got %d", len(items))
	}
	if got := items[0]["decoded_keys"]; got != nil {
		t.Fatalf("expected decoded_keys to be omitted, got %#v", got)
	}
	gotNames, ok := items[0]["key_names"].([]string)
	if !ok {
		t.Fatalf("expected key_names []string, got %#v", items[0]["key_names"])
	}
	if len(gotNames) != 2 || gotNames[0] != "password" || gotNames[1] != "username" {
		t.Fatalf("unexpected key_names %#v", gotNames)
	}
}

func TestBuildAPIServerURL(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		path   string
		expect string
	}{
		{name: "plain host", host: "demo.local", path: "/api/v1/namespaces", expect: "https://demo.local:6443/api/v1/namespaces"},
		{name: "https custom port", host: "https://demo.local:9443", path: "/api/v1/pods", expect: "https://demo.local:9443/api/v1/pods"},
		{name: "path without leading slash", host: "demo.local:8443", path: "apis/apps/v1/deployments", expect: "https://demo.local:8443/apis/apps/v1/deployments"},
	}

	for _, tc := range cases {
		if got := buildAPIServerURL(tc.host, tc.path); got != tc.expect {
			t.Fatalf("%s: buildAPIServerURL(%q, %q) = %q, want %q", tc.name, tc.host, tc.path, got, tc.expect)
		}
	}
}
