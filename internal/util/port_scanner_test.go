package util

import "testing"

func TestParsePortSpec(t *testing.T) {
	ports, err := ParsePortSpec("80,443,8000-8002,443")
	if err != nil {
		t.Fatalf("expected ports to parse, got error: %v", err)
	}
	got := []int{}
	for _, port := range ports {
		got = append(got, port.Port)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}
