package handler

import (
	"strings"
	"testing"
)

func TestEncodeKubeletCommandFormEscapesShellOperators(t *testing.T) {
	encoded := encodeKubeletCommandForm(`sh -c "echo a=b && id"`)
	if !strings.HasPrefix(encoded, "cmd=") {
		t.Fatalf("expected form body to start with cmd=, got %q", encoded)
	}
	if strings.Contains(encoded, "&&") || strings.Contains(encoded, "a=b") {
		t.Fatalf("expected shell operators and equals sign to be url-escaped, got %q", encoded)
	}
	if !strings.Contains(encoded, "%26%26") {
		t.Fatalf("expected && to be encoded, got %q", encoded)
	}
	if !strings.Contains(encoded, "a%3Db") {
		t.Fatalf("expected equals sign to be encoded, got %q", encoded)
	}
}
