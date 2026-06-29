package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/evaluate"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

type InfoHandler struct {
	evalEngine *evaluate.Engine
}

func NewInfoHandler() *InfoHandler {
	return &InfoHandler{
		evalEngine: evaluate.NewEngine(),
	}
}

func (h *InfoHandler) GetProfiles(c *gin.Context) {
	profiles := h.evalEngine.ListProfiles()
	result := make([]gin.H, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, gin.H{
			"id":          p.ID,
			"name":        p.Name,
			"description": p.Description,
			"checks":      len(p.Checks),
		})
	}
	c.JSON(http.StatusOK, result)
}

func (h *InfoHandler) RunProfile(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host"`
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
	if req.TargetHost == "" {
		req.TargetHost = "localhost"
	}

	profileID := c.Param("id")
	target := &evaluate.TargetInfo{
		Host:       req.TargetHost,
		Port:       6443,
		Token:      req.Token,
		SkipTLS:    req.SkipTLS,
		TimeoutSec: req.TimeoutSec,
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	result, err := h.evalEngine.Run(ctx, profileID, target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *InfoHandler) PortScan(c *gin.Context) {
	var req struct {
		Host       string `json:"host" binding:"required"`
		Ports      string `json:"ports"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 3
	}
	var result *util.PortScanResult
	if strings.TrimSpace(req.Ports) == "" {
		result = util.QuickPortScan(req.Host, req.TimeoutSec)
	} else {
		ports, err := util.ParsePortSpec(req.Ports)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result = util.ScanPorts(req.Host, ports, req.TimeoutSec)
	}
	c.JSON(http.StatusOK, result)
}

func (h *InfoHandler) DecodeCapabilities(c *gin.Context) {
	var req struct {
		Hex string `json:"hex" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := util.DecodeCapabilities(req.Hex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *InfoHandler) GetEnvCheckCmds(c *gin.Context) {
	cmds := []gin.H{
		{"cmd": "ls -la /.dockerenv", "desc": "检查是否存在 .dockerenv 文件"},
		{"cmd": "cat /proc/1/cgroup", "desc": "检查cgroup信息 (Docker: /docker/; K8s: /kubepods/)"},
		{"cmd": "env | grep -i kube", "desc": "检查环境变量是否包含K8s相关信息"},
		{"cmd": "ls -la /var/run/secrets/kubernetes.io/serviceaccount/", "desc": "检查是否存在K8s service account目录"},
		{"cmd": "hostname", "desc": "检查hostname (K8s pod通常有特殊命名格式)"},
		{"cmd": "mount | grep -i kube", "desc": "检查mount信息"},
		{"cmd": "cat /etc/resolv.conf", "desc": "检查DNS配置 (K8s环境通常包含cluster.local)"},
		{"cmd": "uname -r", "desc": "检查内核版本 (用于判断内核漏洞可利用性)"},
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}

func (h *InfoHandler) GetPrivCheckCmds(c *gin.Context) {
	cmds := []gin.H{
		{"cmd": "capsh --print", "desc": "打印当前Capabilities (推荐)"},
		{"cmd": "cat /proc/1/status | grep -i cap", "desc": "获取Capabilities hex值 (备用)"},
		{"cmd": "cat /proc/1/status | grep -i seccomp", "desc": "检查是否为特权容器 (seccomp=0)"},
		{"cmd": "ls /dev", "desc": "检查是否可以访问宿主机设备"},
		{"cmd": "mount | grep -E '(host|docker\\\\.sock|kubelet)'", "desc": "检查是否挂载了敏感目录"},
		{"cmd": "ls -la /var/run/docker.sock", "desc": "检查是否有docker.sock (容器逃逸关键)"},
		{"cmd": "id | grep docker", "desc": "检查是否在docker组"},
		{"cmd": "find / -name core_pattern 2>/dev/null", "desc": "检查是否挂载了宿主机procfs"},
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}

func (h *InfoHandler) GetSATokenCmds(c *gin.Context) {
	cmds := []gin.H{
		{"cmd": "cat /var/run/secrets/kubernetes.io/serviceaccount/token", "desc": "读取当前Pod的SA Token"},
		{"cmd": "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace", "desc": "查看当前namespace"},
		{"cmd": "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "desc": "查看K8s CA证书"},
		{"cmd": "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc:443/api/v1/namespaces/", "desc": "使用SA Token访问APIServer"},
		{"cmd": "kubectl --server=https://<API_SERVER>:6443 --token=$TOKEN --insecure-skip-tls-verify=true auth can-i --list", "desc": "使用kubectl配合Token检查权限"},
		{"cmd": "kubectl --server=https://<API_SERVER>:6443 --token=$TOKEN --insecure-skip-tls-verify=true get nodes", "desc": "使用Token获取集群节点信息"},
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}

func (h *InfoHandler) GetPortReference(c *gin.Context) {
	type portEntry struct {
		Port    int    `json:"port"`
		Service string `json:"service"`
	}
	ports := make([]portEntry, len(util.K8sPorts))
	for i, p := range util.K8sPorts {
		ports[i] = portEntry{Port: p.Port, Service: p.Service}
	}
	c.JSON(http.StatusOK, gin.H{"ports": ports})
}
