package handler

import "testing"

func TestParseKubeletPodListAndFlatten(t *testing.T) {
	body := []byte(`{
  "items": [
    {
      "metadata": { "name": "api-pod", "namespace": "kube-system" },
      "spec": {
        "nodeName": "node-1",
        "containers": [
          { "name": "apiserver", "image": "registry.k8s.io/kube-apiserver:v1.29.0" }
        ]
      },
      "status": { "phase": "Running", "podIP": "10.0.0.10" }
    },
    {
      "metadata": { "name": "worker-pod" },
      "spec": {
        "containers": [
          { "name": "worker", "image": "alpine:3.20" }
        ]
      },
      "status": {}
    }
  ]
}`)

	items, err := parseKubeletPodList(body)
	if err != nil {
		t.Fatalf("expected kubelet pod list to parse, got error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(items))
	}

	rows := flattenKubeletPods(items)
	if len(rows) != 2 {
		t.Fatalf("expected 2 flattened rows, got %d", len(rows))
	}
	if rows[0]["namespace"] != "kube-system" || rows[0]["name"] != "api-pod" {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
	if rows[1]["namespace"] != "default" {
		t.Fatalf("expected empty namespace to default to default, got %#v", rows[1]["namespace"])
	}
	if rows[1]["status"] != "Unknown" {
		t.Fatalf("expected missing phase to default to Unknown, got %#v", rows[1]["status"])
	}
}

func TestShellQuoteSingleEscapesQuotes(t *testing.T) {
	input := "ssh-rsa AAAA comment's laptop"
	got := shellQuoteSingle(input)
	want := "'ssh-rsa AAAA comment'\\''s laptop'"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestKubeletExecHasMarkerRequiresSentinel(t *testing.T) {
	if kubeletExecHasMarker(200, []byte("FAILED"), nil, "SSH_KEY_INJECTED") {
		t.Fatalf("expected FAILED output to be rejected")
	}
	if !kubeletExecHasMarker(200, []byte("SSH_KEY_INJECTED"), nil, "SSH_KEY_INJECTED") {
		t.Fatalf("expected sentinel output to be accepted")
	}
	if kubeletExecHasMarker(500, []byte("SSH_KEY_INJECTED"), nil, "SSH_KEY_INJECTED") {
		t.Fatalf("expected non-200 status to be rejected")
	}
}
