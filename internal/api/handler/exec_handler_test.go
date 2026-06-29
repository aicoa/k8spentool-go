package handler

import "testing"

func TestNormalizeReverseShellType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty defaults to bash-i", input: "", want: "bash-i"},
		{name: "default alias", input: "default", want: "bash-i"},
		{name: "nc alias", input: "nc", want: "nc-mkfifo"},
		{name: "keeps supported type", input: "python", want: "python"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeReverseShellType(tt.input); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
