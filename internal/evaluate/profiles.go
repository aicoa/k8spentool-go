package evaluate

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

func (e *Engine) registerProfiles() {
	e.RegisterProfile(e.basicProfile())
	e.RegisterProfile(e.extendedProfile())
}

func (e *Engine) basicProfile() *Profile {
	return &Profile{
		ID:          "basic",
		Name:        "Basic",
		Description: "Fast environment detection and K8s exposure assessment",
		Checks: []Check{
			{
				ID: "is_container", Name: "Container Detection", Category: "environment",
				Description: "Check if running inside a container",
				RiskLevel:   RiskInfo,
				Executor:    checkIsContainer,
			},
			{
				ID: "is_k8s_pod", Name: "K8s Pod Detection", Category: "environment",
				Description: "Check if running inside a K8s pod",
				RiskLevel:   RiskInfo,
				Executor:    checkIsK8sPod,
			},
			{
				ID: "available_caps", Name: "Available Capabilities", Category: "privilege",
				Description: "Check Linux capabilities available in container",
				RiskLevel:   RiskMedium,
				Executor:    checkCapabilities,
			},
			{
				ID: "privileged_mode", Name: "Privileged Mode", Category: "privilege",
				Description: "Check if container is running in privileged mode",
				RiskLevel:   RiskHigh,
				Executor:    checkPrivileged,
			},
			{
				ID: "host_mounts", Name: "Host Mount Points", Category: "escape",
				Description: "Check for host filesystem mounts",
				RiskLevel:   RiskHigh,
				Executor:    checkHostMounts,
			},
			{
				ID: "docker_sock", Name: "Docker Socket Access", Category: "escape",
				Description: "Check if docker.sock is mounted and accessible",
				RiskLevel:   RiskCritical,
				Executor:    checkDockerSocket,
			},
			{
				ID: "sa_token", Name: "ServiceAccount Token", Category: "k8s_access",
				Description: "Check if SA token is mounted in pod",
				RiskLevel:   RiskMedium,
				Executor:    checkSAToken,
			},
			{
				ID: "k8s_api_access", Name: "K8s API Access", Category: "k8s_access",
				Description: "Test if K8s API server is reachable from pod",
				RiskLevel:   RiskMedium,
				Executor:    checkK8sAPIAccess,
			},
			{
				ID: "cloud_metadata", Name: "Cloud Metadata API", Category: "cloud",
				Description: "Check if cloud provider metadata API is accessible",
				RiskLevel:   RiskHigh,
				Executor:    checkCloudMetadata,
			},
		},
	}
}

func (e *Engine) extendedProfile() *Profile {
	return &Profile{
		ID:          "extended",
		Name:        "Extended",
		Description: "Extended evaluation including sensitive file scan and K8s component enumeration",
		Checks: append(e.basicProfile().Checks,
			Check{
				ID: "sensitive_files", Name: "Sensitive Files", Category: "info",
				Description: "Scan for sensitive files (SSH keys, credentials, configs)",
				RiskLevel:   RiskHigh,
				Executor:    checkSensitiveFiles,
			},
			Check{
				ID: "k8s_anonymous", Name: "K8s Anonymous Access", Category: "k8s_access",
				Description: "Check if K8s API allows anonymous access",
				RiskLevel:   RiskCritical,
				Executor:    checkK8sAnonymous,
			},
			Check{
				ID: "kubelet_access", Name: "Kubelet Access", Category: "k8s_access",
				Description: "Check if Kubelet API is accessible",
				RiskLevel:   RiskCritical,
				Executor:    checkKubeletAccess,
			},
			Check{
				ID: "etcd_access", Name: "Etcd Access", Category: "k8s_access",
				Description: "Check if Etcd is accessible without auth",
				RiskLevel:   RiskCritical,
				Executor:    checkEtcdAccess,
			},
		),
	}
}

// Check implementors
//
// NOTE: The following checks (checkIsContainer, checkIsK8sPod, checkCapabilities, checkPrivileged,
// checkHostMounts, checkDockerSocket, checkSAToken, checkSensitiveFiles) operate on the LOCAL
// filesystem of the machine running K8sPenTool-ng. They are designed for scenarios where the
// tool is deployed inside a container on the target cluster (e.g. via kubectl cp + exec).
// When running the tool from an external workstation, these checks reflect the workstation's
// environment, NOT the target cluster. Use the exec_list_pods + exec_command AI tools or the
// Exec Tab to run these checks remotely inside target pods.
//
// Network-based checks (checkK8sAnonymous, checkKubeletAccess, checkEtcdAccess, checkK8sAPIAccess,
// checkCloudMetadata) correctly use TargetInfo.Host to probe the remote target.

func checkIsContainer(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	found := false
	indicators := []string{
		"/.dockerenv", "/run/.containerenv", "/proc/1/cgroup",
	}
	for _, p := range indicators {
		if _, err := os.Stat(p); err == nil {
			found = true
			break
		}
	}
	// Also check cgroup for docker/kube
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kube") || strings.Contains(content, "containerd") {
			found = true
		}
	}
	return &CheckResult{
		CheckID: "is_container", CheckName: "Container Detection",
		Category: "environment", Success: true, Found: found, RiskLevel: RiskInfo,
		Summary: boolToSummary(found, "Running inside container", "Not in a container"),
	}, nil
}

func checkIsK8sPod(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	found := false
	details := make(map[string]string)
	saDir := "/var/run/secrets/kubernetes.io/serviceaccount/"
	if _, err := os.Stat(saDir); err == nil {
		found = true
		if data, err := os.ReadFile(saDir + "namespace"); err == nil {
			details["namespace"] = strings.TrimSpace(string(data))
		}
	}
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		found = true
		details["k8s_host"] = host
		details["k8s_port"] = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	return &CheckResult{
		CheckID: "is_k8s_pod", CheckName: "K8s Pod Detection",
		Category: "environment", Success: true, Found: found, RiskLevel: RiskInfo,
		Summary: boolToSummary(found, "Running in K8s pod", "Not in K8s pod"),
		Details: details,
	}, nil
}

func checkCapabilities(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	data, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return &CheckResult{CheckID: "available_caps", CheckName: "Capabilities",
			Category: "privilege", Success: false, Error: err.Error()}, nil
	}
	mask, err := extractCapabilityMask(string(data))
	if err != nil {
		return &CheckResult{
			CheckID:   "available_caps",
			CheckName: "Capabilities",
			Category:  "privilege",
			Success:   false,
			Error:     err.Error(),
			Summary:   "Failed to extract capabilities from /proc/1/status",
		}, nil
	}
	decoded, err := util.DecodeCapabilities(mask)
	if err != nil {
		return &CheckResult{
			CheckID:   "available_caps",
			CheckName: "Capabilities",
			Category:  "privilege",
			Success:   false,
			Error:     err.Error(),
			Summary:   "Failed to decode capability bitmask",
		}, nil
	}
	foundCaps := make([]string, 0, len(decoded.Dangerous))
	for _, cap := range decoded.Dangerous {
		foundCaps = append(foundCaps, cap.Name)
	}
	return &CheckResult{
		CheckID: "available_caps", CheckName: "Capabilities",
		Category: "privilege", Success: true,
		Found:     len(foundCaps) > 0 || decoded.HasAll,
		RiskLevel: riskFromCaps(foundCaps),
		Summary:   fmt.Sprintf("Dangerous capabilities: %v", foundCaps),
		Details:   decoded,
	}, nil
}

func extractCapabilityMask(status string) (string, error) {
	re := regexp.MustCompile(`(?m)^CapEff:\s*([0-9a-fA-F]+)\s*$`)
	if match := re.FindStringSubmatch(status); len(match) > 1 {
		return match[1], nil
	}
	re = regexp.MustCompile(`(?m)^CapPrm:\s*([0-9a-fA-F]+)\s*$`)
	if match := re.FindStringSubmatch(status); len(match) > 1 {
		return match[1], nil
	}
	return "", fmt.Errorf("CapEff/CapPrm not found in process status")
}

func checkPrivileged(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	// Check seccomp profile (0 means disabled = privileged)
	data, _ := os.ReadFile("/proc/1/status")
	privileged := strings.Contains(string(data), "Seccomp:\t0\n")

	if !privileged {
		// Check if we can access host devices
		if _, err := os.Stat("/dev/sda"); err == nil {
			privileged = true
		}
	}
	return &CheckResult{
		CheckID: "privileged_mode", CheckName: "Privileged Mode",
		Category: "privilege", Success: true, Found: privileged,
		RiskLevel: riskBool(privileged, RiskCritical, RiskLow),
		Summary:   boolToSummary(privileged, "Privileged container detected!", "Not privileged"),
	}, nil
}

func checkHostMounts(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	data, err := os.ReadFile("/proc/1/mountinfo")
	if err != nil {
		data, _ = os.ReadFile("/proc/mounts")
	}
	content := string(data)
	hasHostMount := strings.Contains(content, "/host") ||
		strings.Contains(content, "hostPath") ||
		strings.Contains(content, "/proc/sys") && strings.Contains(content, "rw")

	return &CheckResult{
		CheckID: "host_mounts", CheckName: "Host Mount Points",
		Category: "escape", Success: true, Found: hasHostMount,
		RiskLevel: riskBool(hasHostMount, RiskHigh, RiskLow),
		Summary:   boolToSummary(hasHostMount, "Host filesystem mounted - escape possible", "No host mounts detected"),
	}, nil
}

func checkDockerSocket(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	_, err := os.Stat("/var/run/docker.sock")
	hasSock := err == nil
	return &CheckResult{
		CheckID: "docker_sock", CheckName: "Docker Socket",
		Category: "escape", Success: true, Found: hasSock,
		RiskLevel: riskBool(hasSock, RiskCritical, RiskLow),
		Summary:   boolToSummary(hasSock, "Docker socket mounted - container breakout via DIND attack possible!", "No docker socket"),
	}, nil
}

func checkSAToken(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	saBase := "/var/run/secrets/kubernetes.io/serviceaccount/"
	tokenFile := saBase + "token"
	data, err := os.ReadFile(tokenFile)
	hasToken := err == nil && len(data) > 0

	details := map[string]string{}
	if hasToken {
		details["token_preview"] = string(data[:min(20, len(data))]) + "..."
	}
	if ns, err := os.ReadFile(saBase + "namespace"); err == nil {
		details["namespace"] = strings.TrimSpace(string(ns))
	}
	return &CheckResult{
		CheckID: "sa_token", CheckName: "ServiceAccount Token",
		Category: "k8s_access", Success: true, Found: hasToken,
		RiskLevel: riskBool(hasToken, RiskMedium, RiskInfo),
		Summary:   boolToSummary(hasToken, "SA token available - can access K8s API", "No SA token found"),
		Details:   details,
	}, nil
}

func checkK8sAPIAccess(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	if t.Host == "" {
		return &CheckResult{CheckID: "k8s_api_access", Category: "k8s_access",
			Summary: "No target host specified"}, nil
	}
	url := fmt.Sprintf("https://%s:%d/api", t.Host, t.Port)
	code, _, err := util.SendRequest(url, "GET", t.Token, t.TimeoutSec, t.SkipTLS)
	accessible := err == nil && code < 500
	return &CheckResult{
		CheckID: "k8s_api_access", CheckName: "K8s API Access",
		Category: "k8s_access", Success: true, Found: accessible,
		RiskLevel: riskBool(accessible, RiskMedium, RiskInfo),
		Summary:   boolToSummary(accessible, fmt.Sprintf("K8s API accessible (HTTP %d)", code), "K8s API not reachable"),
	}, nil
}

func checkCloudMetadata(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	metadataURLs := map[string]string{
		"AWS":          "http://169.254.169.254/latest/meta-data/",
		"GCP":          "http://metadata.google.internal/computeMetadata/v1/",
		"Azure":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"Alibaba":      "http://100.100.100.200/latest/meta-data/",
		"DigitalOcean": "http://169.254.169.254/metadata/v1.json",
	}
	accessible := []string{}
	for provider, url := range metadataURLs {
		code, _, err := util.SendRequest(url, "GET", "", 3, false)
		if err == nil && code < 500 {
			accessible = append(accessible, provider)
		}
	}
	return &CheckResult{
		CheckID: "cloud_metadata", CheckName: "Cloud Metadata",
		Category: "cloud", Success: true, Found: len(accessible) > 0,
		RiskLevel: riskBool(len(accessible) > 0, RiskHigh, RiskInfo),
		Summary:   boolToSummary(len(accessible) > 0, fmt.Sprintf("Cloud metadata accessible: %v", accessible), "No cloud metadata access"),
		Details:   accessible,
	}, nil
}

func checkSensitiveFiles(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	sensitivePaths := []string{
		"/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
		"/etc/shadow", "/etc/passwd",
		"/etc/kubernetes/admin.conf", "/root/.kube/config",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/proc/1/environ",
	}
	found := []string{}
	for _, p := range sensitivePaths {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	return &CheckResult{
		CheckID: "sensitive_files", CheckName: "Sensitive Files",
		Category: "info", Success: true, Found: len(found) > 0,
		RiskLevel: riskBool(len(found) > 0, RiskHigh, RiskMedium),
		Summary:   fmt.Sprintf("Found %d sensitive files: %v", len(found), found),
		Details:   found,
	}, nil
}

func checkK8sAnonymous(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	url := fmt.Sprintf("https://%s:%d/api/v1/namespaces", t.Host, t.Port)
	code, body, err := util.SendRequest(url, "GET", "", t.TimeoutSec, t.SkipTLS)
	anonymous := err == nil && (code == 200 || code == 403)
	canList := err == nil && code == 200
	return &CheckResult{
		CheckID: "k8s_anonymous", CheckName: "K8s Anonymous Access",
		Category: "k8s_access", Success: true, Found: anonymous,
		RiskLevel: riskBool(canList, RiskCritical, riskBool(anonymous, RiskHigh, RiskInfo)),
		Summary:   boolToSummary(canList, "CRITICAL: Anonymous access with resource listing!", boolToSummary(anonymous, "Anonymous access detected (limited)", "No anonymous access")),
		Details:   map[string]interface{}{"status_code": code, "body_preview": string(body[:min(200, len(body))])},
	}, nil
}

func checkKubeletAccess(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	url := fmt.Sprintf("https://%s:10250/pods", t.Host)
	code, body, err := util.SendRequest(url, "GET", "", t.TimeoutSec, t.SkipTLS)
	accessible := err == nil && code == 200
	return &CheckResult{
		CheckID: "kubelet_access", CheckName: "Kubelet Access",
		Category: "k8s_access", Success: true, Found: accessible,
		RiskLevel: riskBool(accessible, RiskCritical, RiskInfo),
		Summary:   boolToSummary(accessible, "CRITICAL: Kubelet accessible without auth! Can exec in pods.", "Kubelet not accessible"),
		Details:   map[string]interface{}{"status_code": code, "body_preview": string(body[:min(200, len(body))])},
	}, nil
}

func checkEtcdAccess(ctx context.Context, t *TargetInfo) (*CheckResult, error) {
	open := util.IsPortOpen(t.Host, 2379, 3)
	if !open {
		return &CheckResult{
			CheckID: "etcd_access", CheckName: "Etcd Access",
			Category: "k8s_access", Success: true, Found: false,
			RiskLevel: RiskInfo, Summary: "Etcd port 2379 not open",
		}, nil
	}
	url := fmt.Sprintf("http://%s:2379/version", t.Host)
	code, body, err := util.SendRequest(url, "GET", "", t.TimeoutSec, false)
	accessible := err == nil && code == 200
	return &CheckResult{
		CheckID: "etcd_access", CheckName: "Etcd Access",
		Category: "k8s_access", Success: true, Found: accessible,
		RiskLevel: riskBool(accessible, RiskCritical, RiskInfo),
		Summary:   boolToSummary(accessible, "CRITICAL: Etcd accessible without auth! Can read all cluster secrets.", "Etcd not accessible"),
		Details:   map[string]interface{}{"status_code": code, "version": string(body[:min(100, len(body))])},
	}, nil
}

// Helpers
func boolToSummary(b bool, trueMsg, falseMsg string) string {
	if b {
		return trueMsg
	}
	return falseMsg
}

func riskBool(b bool, trueRisk, falseRisk RiskLevel) RiskLevel {
	if b {
		return trueRisk
	}
	return falseRisk
}

func riskFromCaps(caps []string) RiskLevel {
	for _, c := range caps {
		switch c {
		case "CAP_SYS_ADMIN":
			return RiskCritical
		case "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH":
			return RiskHigh
		case "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_RAWIO":
			return RiskMedium
		}
	}
	return RiskLow
}
