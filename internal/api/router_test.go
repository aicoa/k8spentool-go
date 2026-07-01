package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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

func TestUnknownAPIRouteDoesNotServeFrontend(t *testing.T) {
	router := SetupRouter(ws.NewHub())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/not-a-real-route", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("expected API 404, got frontend html: %q", rec.Body.String())
	}
}

func TestRootServesFrontendIndex(t *testing.T) {
	router := SetupRouter(ws.NewHub())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := strings.ToLower(rec.Body.String()); !strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected frontend index html, got %q", rec.Body.String())
	}
}

func TestOpenAPISpecCoversRegisteredPaths(t *testing.T) {
	routerSourcePath := mustSourcePath(t, "router.go")
	routerSource, err := os.ReadFile(routerSourcePath)
	if err != nil {
		t.Fatalf("read router source: %v", err)
	}
	openapiBody, err := os.ReadFile(openAPISpecPath())
	if err != nil {
		t.Fatalf("read openapi spec: %v", err)
	}

	groupRe := regexp.MustCompile(`(\w+) := v1\.Group\("([^"]+)"\)`)
	rootRouteRe := regexp.MustCompile(`v1\.(GET|POST|PUT|DELETE)\("([^"]+)"`)
	groupRouteRe := regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE)\("([^"]+)"`)
	paramRe := regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)`)

	groupBases := map[string]string{}
	for _, match := range groupRe.FindAllStringSubmatch(string(routerSource), -1) {
		groupBases[match[1]] = "/api/v1" + match[2]
	}

	paths := map[string]struct{}{}
	for _, match := range rootRouteRe.FindAllStringSubmatch(string(routerSource), -1) {
		paths[normalizeRoutePath(match[2], paramRe)] = struct{}{}
	}
	for _, match := range groupRouteRe.FindAllStringSubmatch(string(routerSource), -1) {
		base, ok := groupBases[match[1]]
		if !ok {
			continue
		}
		paths[normalizeRoutePath(base+match[3], paramRe)] = struct{}{}
	}

	missing := make([]string, 0)
	spec := string(openapiBody)
	for path := range paths {
		if !strings.Contains(spec, path) {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("openapi spec missing registered paths: %v", missing)
	}
}

func mustSourcePath(t *testing.T, name string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(currentFile), name)
}

func normalizeRoutePath(path string, paramRe *regexp.Regexp) string {
	if !strings.HasPrefix(path, "/api/v1") {
		path = "/api/v1" + path
	}
	path = strings.TrimPrefix(path, "/api/v1")
	return paramRe.ReplaceAllString(path, `{$1}`)
}
