package evaluate

import (
	"context"
	"fmt"
	"strings"

	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

func runRemotePodCheck(ctx context.Context, check Check, target *TargetInfo) (*CheckResult, error) {
	if target.Namespace == "" || target.PodName == "" {
		return nil, fmt.Errorf("remote-pod-exec requires namespace and pod_name")
	}
	client, err := kubectl.NewTargetClient(target.Host, target.Token, target.Username, target.Password, target.SkipTLS)
	if err != nil {
		return nil, err
	}
	switch check.ID {
	case "is_container":
		out, err := remoteShell(ctx, client, target, `test -f /.dockerenv -o -f /run/.containerenv; echo file=$?; grep -E 'docker|kube|containerd' /proc/1/cgroup 2>/dev/null | head -1`)
		found := err == nil && (strings.Contains(out, "file=0") || strings.Contains(out, "docker") || strings.Contains(out, "kube") || strings.Contains(out, "containerd"))
		return remoteBoolResult(check, found, "Running inside container", "Not in a container", out, err), nil
	case "is_k8s_pod":
		out, err := remoteShell(ctx, client, target, `test -d /var/run/secrets/kubernetes.io/serviceaccount; echo sa=$?; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null; env | grep -E '^KUBERNETES_SERVICE_(HOST|PORT)=' 2>/dev/null`)
		found := err == nil && (strings.Contains(out, "sa=0") || strings.Contains(out, "KUBERNETES_SERVICE_HOST="))
		return remoteBoolResult(check, found, "Running in K8s pod", "Not in K8s pod", out, err), nil
	case "available_caps":
		out, err := remoteShell(ctx, client, target, `cat /proc/1/status 2>/dev/null | grep -E '^(CapEff|CapPrm):'`)
		if err != nil {
			return remoteBoolResult(check, false, "", "Failed to read capabilities", out, err), nil
		}
		mask, err := extractCapabilityMask(out)
		if err != nil {
			return remoteBoolResult(check, false, "", "Failed to extract capabilities", out, err), nil
		}
		decoded, err := util.DecodeCapabilities(mask)
		if err != nil {
			return remoteBoolResult(check, false, "", "Failed to decode capability bitmask", out, err), nil
		}
		foundCaps := make([]string, 0, len(decoded.Dangerous))
		for _, cap := range decoded.Dangerous {
			foundCaps = append(foundCaps, cap.Name)
		}
		return &CheckResult{
			CheckID: check.ID, CheckName: check.Name, Category: check.Category, Success: true,
			Found: len(foundCaps) > 0 || decoded.HasAll, RiskLevel: riskFromCaps(foundCaps),
			Summary: fmt.Sprintf("Dangerous capabilities: %v", foundCaps), Details: decoded,
		}, nil
	case "privileged_mode":
		out, err := remoteShell(ctx, client, target, `grep -q $'Seccomp:\t0' /proc/1/status 2>/dev/null; echo seccomp=$?; test -e /dev/sda; echo devsda=$?`)
		found := err == nil && (strings.Contains(out, "seccomp=0") || strings.Contains(out, "devsda=0"))
		return remoteBoolResult(check, found, "Privileged container detected!", "Not privileged", out, err), nil
	case "host_mounts":
		out, err := remoteShell(ctx, client, target, `cat /proc/1/mountinfo /proc/mounts 2>/dev/null | grep -E '(/host|hostPath|/proc/sys)' | head -20`)
		found := err == nil && strings.TrimSpace(out) != ""
		return remoteBoolResult(check, found, "Host filesystem mounted - escape possible", "No host mounts detected", out, err), nil
	case "docker_sock":
		out, err := remoteShell(ctx, client, target, `test -S /var/run/docker.sock -o -e /var/run/docker.sock; echo docker_sock=$?`)
		found := err == nil && strings.Contains(out, "docker_sock=0")
		return remoteBoolResult(check, found, "Docker socket mounted - container breakout via DIND attack possible!", "No docker socket", out, err), nil
	case "sa_token":
		out, err := remoteShell(ctx, client, target, `test -s /var/run/secrets/kubernetes.io/serviceaccount/token; echo token=$?; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null`)
		found := err == nil && strings.Contains(out, "token=0")
		return remoteBoolResult(check, found, "SA token available - can access K8s API", "No SA token found", out, err), nil
	case "sensitive_files":
		out, err := remoteShell(ctx, client, target, `for p in /root/.ssh/id_rsa /root/.ssh/authorized_keys /etc/shadow /etc/passwd /etc/kubernetes/admin.conf /root/.kube/config /var/run/secrets/kubernetes.io/serviceaccount/token /proc/1/environ; do test -e "$p" && echo "$p"; done`)
		found := err == nil && strings.TrimSpace(out) != ""
		return remoteBoolResult(check, found, "Sensitive files found", "No sensitive files found", out, err), nil
	default:
		return nil, fmt.Errorf("remote-pod-exec not implemented for check %s", check.ID)
	}
}

func remoteShell(ctx context.Context, client *kubectl.Client, target *TargetInfo, script string) (string, error) {
	res, err := client.ExecInPodResult(ctx, target.Namespace, target.PodName, target.Container, []string{"sh", "-c", script})
	if res == nil {
		return "", err
	}
	out := strings.TrimSpace(res.Stdout)
	if res.Stderr != "" {
		out = strings.TrimSpace(out + "\n" + res.Stderr)
	}
	return out, err
}

func remoteBoolResult(check Check, found bool, trueSummary, falseSummary, output string, err error) *CheckResult {
	success := err == nil
	summary := boolToSummary(found, trueSummary, falseSummary)
	if err != nil {
		summary = falseSummary
	}
	return &CheckResult{
		CheckID: check.ID, CheckName: check.Name, Category: check.Category,
		Success: success, Found: found, RiskLevel: riskBool(found, check.RiskLevel, RiskInfo),
		Summary: summary, Error: errorString(err), Details: map[string]string{"mode": "remote-pod-exec", "output": output},
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
