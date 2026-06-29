package evaluate

import "testing"

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
