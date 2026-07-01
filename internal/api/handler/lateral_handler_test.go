package handler

import "testing"

func TestNewLateralClientAllowsAnonymous(t *testing.T) {
	client, err := newLateralClient("demo.local", "", "", "", true)
	if err != nil {
		t.Fatalf("expected anonymous client to be created, got error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected client, got nil")
	}
}
