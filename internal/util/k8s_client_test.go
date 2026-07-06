package util

import (
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

func TestApplyAuthHeadersUsesBasicAuthWhenUsernamePasswordProvided(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}

	applyAuthHeaders(req, "", "alice", "secret")

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("expected basic auth header %q, got %q", want, got)
	}
}

func TestApplyAuthHeadersPrefersBearerTokenOverBasicAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}

	applyAuthHeaders(req, "demo-token", "alice", "secret")

	if got := req.Header.Get("Authorization"); got != "Bearer demo-token" {
		t.Fatalf("expected bearer token header, got %q", got)
	}
}

func TestNewRequestWithAuthHonorsMethodBodyAndContentType(t *testing.T) {
	req, err := newRequestWithAuth(
		http.MethodPut,
		"https://example.test/apis/apps/v1",
		`{"hello":"world"}`,
		"application/merge-patch+json",
		"",
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("newRequestWithAuth returned error: %v", err)
	}
	if req.Method != http.MethodPut {
		t.Fatalf("expected method PUT, got %q", req.Method)
	}
	bodyBytes, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("failed to read request body: %v", readErr)
	}
	if got := string(bodyBytes); got != `{"hello":"world"}` {
		t.Fatalf("unexpected request body %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/merge-patch+json" {
		t.Fatalf("unexpected content type %q", got)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if got := req.Header.Get("Authorization"); got != wantAuth {
		t.Fatalf("expected auth header %q, got %q", wantAuth, got)
	}
}
