package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestKubectlDeleteRequiresYAMLOrResourceName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewKubectlHandler()
	router.POST("/kubectl/delete", handler.Delete)

	req := httptest.NewRequest(http.MethodPost, "/kubectl/delete", strings.NewReader(`{"target_host":"demo.local"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when delete mode is missing, got %d", rec.Code)
	}
}

func TestIsClusterScopedResourceAlias(t *testing.T) {
	cases := map[string]bool{
		"crb":                 true,
		"clusterrolebinding":  true,
		"clusterrolebindings": true,
		"clusterrole":         true,
		"namespaces":          true,
		"pod":                 false,
		"deployment":          false,
		"serviceaccount":      false,
	}

	for resource, want := range cases {
		if got := isClusterScopedResourceAlias(resource); got != want {
			t.Fatalf("resource %q expected cluster-scoped=%v, got %v", resource, want, got)
		}
	}
}

func TestAuthCanINamespaceForClusterScopedResource(t *testing.T) {
	if got := authCanINamespaceForResource("default", "clusterrolebindings"); got != "" {
		t.Fatalf("expected cluster-scoped resource to ignore namespace, got %q", got)
	}
	if got := authCanINamespaceForResource("kube-system", "pods"); got != "kube-system" {
		t.Fatalf("expected namespaced resource to keep namespace, got %q", got)
	}
}

func TestFormatDeleteCommandOmitsNamespaceForClusterScopedResource(t *testing.T) {
	if got := formatDeleteCommand("clusterrolebinding", "admin-bind", ""); got != "kubectl delete clusterrolebinding admin-bind" {
		t.Fatalf("unexpected cluster-scoped delete command: %q", got)
	}
	if got := formatDeleteMessage("clusterrolebinding", "admin-bind", ""); got != "deleted clusterrolebinding/admin-bind" {
		t.Fatalf("unexpected cluster-scoped delete message: %q", got)
	}
	if got := formatDeleteCommand("pod", "demo", "default"); got != "kubectl delete pod demo -n default" {
		t.Fatalf("unexpected namespaced delete command: %q", got)
	}
}
