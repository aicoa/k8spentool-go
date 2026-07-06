package kubectl

import (
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

func TestBuildSPDYURLUsesPortForwardSubresource(t *testing.T) {
	client := &Client{
		config: &rest.Config{Host: "https://demo.local:6443"},
	}

	u, err := client.BuildSPDYURL("default", "demo-pod")
	if err != nil {
		t.Fatalf("expected URL, got error: %v", err)
	}
	if !strings.Contains(u.Path, "/pods/demo-pod/portforward") {
		t.Fatalf("expected portforward subresource path, got %s", u.Path)
	}
	if strings.Contains(u.Path, "/exec") {
		t.Fatalf("expected BuildSPDYURL to avoid exec subresource, got %s", u.Path)
	}
}
