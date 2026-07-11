package evaluate

import (
	"context"
	"strings"
	"testing"
)

func TestExtractCapabilityMask(t *testing.T) {
	status := "Name:\ttest\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\n"
	mask, err := extractCapabilityMask(status)
	if err != nil {
		t.Fatalf("expected CapEff to be extracted, got error: %v", err)
	}
	if mask != "00000000a80425fb" {
		t.Fatalf("unexpected mask: %q", mask)
	}
}

func TestRemoteK8sModeSkipsLocalOnlyChecks(t *testing.T) {
	engine := NewEngine()
	result, err := engine.Run(context.Background(), "basic", &TargetInfo{
		Host:       "127.0.0.1",
		Port:       6443,
		TimeoutSec: 1,
		Mode:       "remote-k8s",
	})
	if err != nil {
		t.Fatalf("expected run to complete, got %v", err)
	}
	var containerCheck *CheckResult
	for i := range result.Results {
		if result.Results[i].CheckID == "is_container" {
			containerCheck = &result.Results[i]
			break
		}
	}
	if containerCheck == nil {
		t.Fatalf("expected is_container result")
	}
	if containerCheck.Success || !strings.Contains(containerCheck.Error, "local-agent mode or remote-pod-exec") {
		t.Fatalf("expected local-only check to be skipped with explicit mode guidance, got %#v", containerCheck)
	}
}
