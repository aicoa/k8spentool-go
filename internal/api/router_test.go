package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trymonoly/K8sPenTool-ng/internal/api/ws"
)

func TestOpenAPIJSONReturnsJSON(t *testing.T) {
	router := SetupRouter(ws.NewHub())

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); len(got) < 16 || got[:16] != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("expected JSON body, got error: %v", err)
	}
	if _, ok := decoded["openapi"]; !ok {
		t.Fatalf("expected openapi field in response")
	}
}

func TestDocsRedirectsToSwagger(t *testing.T) {
	router := SetupRouter(ws.NewHub())

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/swagger/" {
		t.Fatalf("expected redirect to /swagger/, got %q", got)
	}
}

func TestSwaggerIndexServed(t *testing.T) {
	router := SetupRouter(ws.NewHub())

	req := httptest.NewRequest(http.MethodGet, "/swagger/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "K8sPenTool-ng API Docs") || !strings.Contains(body, "/openapi.json") {
		t.Fatalf("expected swagger index html, got %q", body)
	}
}
