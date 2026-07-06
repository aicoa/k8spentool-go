package handler

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KubectlHandler struct{}

func NewKubectlHandler() *KubectlHandler { return &KubectlHandler{} }

type kubectlRequest struct {
	TargetHost string `json:"target_host" binding:"required"`
	Token      string `json:"token"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	SkipTLS    bool   `json:"skip_tls"`
	TimeoutSec int    `json:"timeout_sec"`
}

func (h *KubectlHandler) buildClient(req *kubectlRequest) (*kubectl.Client, error) {
	return kubectl.NewTargetClient(req.TargetHost, req.Token, req.Username, req.Password, req.SkipTLS)
}

func (h *KubectlHandler) getTimeout(req *kubectlRequest) time.Duration {
	if req.TimeoutSec <= 0 {
		return 10 * time.Second
	}
	return time.Duration(req.TimeoutSec) * time.Second
}

func podListToJSON(pods []podInfo) []gin.H {
	result := make([]gin.H, 0, len(pods))
	for _, p := range pods {
		result = append(result, gin.H{
			"namespace": p.Namespace, "name": p.Name, "status": p.Status,
			"node": p.Node, "ip": p.IP, "containers": p.Containers, "images": p.Images,
		})
	}
	return result
}

type podInfo struct {
	Namespace, Name, Status, Node, IP, Containers, Images string
}

var authCanIResourceSet = []string{
	"pods", "secrets", "services", "deployments", "daemonsets", "statefulsets", "cronjobs",
	"ingresses", "networkpolicies", "persistentvolumeclaims", "persistentvolumes",
	"nodes", "serviceaccounts", "configmaps", "namespaces",
	"roles", "rolebindings", "clusterroles", "clusterrolebindings",
}

var authCanIVerbs = []string{"get", "list", "create", "delete", "update", "patch"}

func listPods(ctx context.Context, client *kubectl.Client, ns string) ([]podInfo, error) {
	podList, err := client.ListPods(ctx, ns)
	if err != nil {
		return nil, err
	}
	pods := make([]podInfo, 0, len(podList.Items))
	for _, p := range podList.Items {
		containers := make([]string, 0)
		images := make([]string, 0)
		for _, c := range p.Spec.Containers {
			containers = append(containers, c.Name)
			images = append(images, c.Image)
		}
		pods = append(pods, podInfo{
			Namespace:  p.Namespace,
			Name:       p.Name,
			Status:     string(p.Status.Phase),
			Node:       p.Spec.NodeName,
			IP:         p.Status.PodIP,
			Containers: strings.Join(containers, ", "),
			Images:     strings.Join(images, ", "),
		})
	}
	return pods, nil
}

func (h *KubectlHandler) GetPods(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	pods, err := listPods(ctx, client, "")
	c.JSON(http.StatusOK, gin.H{"pods": podListToJSON(pods), "total": len(pods), "error": errStr(err)})
}

func (h *KubectlHandler) GetNodes(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	nodeList, err := client.ListNodes(ctx)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	nodes := make([]gin.H, 0, len(nodeList.Items))
	for _, n := range nodeList.Items {
		ip := ""
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" {
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

func getNodeReady(n *corev1.Node) string {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return "Ready"
		}
	}
	return "NotReady"
}

func (h *KubectlHandler) GetServices(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	svcList, err := client.ListServices(ctx, "")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	svcs := make([]gin.H, 0, len(svcList.Items))
	for _, s := range svcList.Items {
		ports := make([]string, 0)
		for _, p := range s.Spec.Ports {
			ports = append(ports, formatPort(p))
		}
		svcs = append(svcs, gin.H{
			"namespace": s.Namespace, "name": s.Name, "type": string(s.Spec.Type),
			"cluster_ip": s.Spec.ClusterIP, "ports": ports,
		})
	}
	c.JSON(http.StatusOK, gin.H{"services": svcs, "total": len(svcs)})
}

func formatPort(p corev1.ServicePort) string {
	s := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
	if p.NodePort > 0 {
		s += fmt.Sprintf("→%d", p.NodePort)
	}
	return s
}

func (h *KubectlHandler) GetSecrets(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	secretList, err := client.ListSecrets(ctx, "")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	secrets := make([]gin.H, 0, len(secretList.Items))
	for _, s := range secretList.Items {
		keyNames := make([]string, 0, len(s.Data))
		for k := range s.Data {
			keyNames = append(keyNames, k)
		}
		sort.Strings(keyNames)
		secrets = append(secrets, gin.H{
			"namespace": s.Namespace, "name": s.Name, "type": string(s.Type),
			"keys": len(s.Data), "key_names": keyNames,
		})
	}
	c.JSON(http.StatusOK, gin.H{"secrets": secrets, "total": len(secrets)})
}

func (h *KubectlHandler) GetDeployments(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	depList, err := client.Clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	deps := make([]gin.H, 0, len(depList.Items))
	for _, d := range depList.Items {
		image := ""
		if len(d.Spec.Template.Spec.Containers) > 0 {
			image = d.Spec.Template.Spec.Containers[0].Image
		}
		replicas := int32(0)
		if d.Spec.Replicas != nil {
			replicas = *d.Spec.Replicas
		}
		deps = append(deps, gin.H{
			"namespace": d.Namespace, "name": d.Name,
			"replicas": replicas, "ready": d.Status.ReadyReplicas, "image": image,
		})
	}
	c.JSON(http.StatusOK, gin.H{"deployments": deps, "total": len(deps)})
}

func (h *KubectlHandler) GetSA(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	saList, err := client.ListServiceAccounts(ctx, "")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	sas := make([]gin.H, 0, len(saList.Items))
	for _, s := range saList.Items {
		secrets := make([]string, 0)
		for _, sec := range s.Secrets {
			secrets = append(secrets, sec.Name)
		}
		sas = append(sas, gin.H{"namespace": s.Namespace, "name": s.Name, "secrets": secrets})
	}
	c.JSON(http.StatusOK, gin.H{"service_accounts": sas, "total": len(sas)})
}

func (h *KubectlHandler) GetCRB(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	crbList, err := client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	crbs := make([]gin.H, 0, len(crbList.Items))
	for _, c := range crbList.Items {
		subjects := make([]string, 0)
		for _, s := range c.Subjects {
			subjects = append(subjects, s.Kind+":"+s.Name)
		}
		crbs = append(crbs, gin.H{
			"name": c.Name, "role": c.RoleRef.Name, "subjects": subjects,
		})
	}
	c.JSON(http.StatusOK, gin.H{"cluster_role_bindings": crbs, "total": len(crbs)})
}

func (h *KubectlHandler) GetImages(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()
	pods, err := listPods(ctx, client, "")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	images := make([]gin.H, 0)
	for _, p := range pods {
		images = append(images, gin.H{"namespace": p.Namespace, "pod": p.Name, "images": p.Images})
	}
	c.JSON(http.StatusOK, gin.H{"images": images, "total": len(images)})
}

func (h *KubectlHandler) ClusterInfo(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	version, err := client.ServerVersion()
	c.JSON(http.StatusOK, gin.H{"version": version, "error": errStr(err)})
}

func (h *KubectlHandler) AuthCanI(c *gin.Context) {
	var req kubectlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.getTimeout(&req))
	defer cancel()

	perms := make([]gin.H, 0)
	for _, r := range authCanIResourceSet {
		allowed := make([]string, 0)
		for _, v := range authCanIVerbs {
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

func (h *KubectlHandler) CustomCommand(c *gin.Context) {
	var req struct {
		kubectlRequest
		Command string `json:"command" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req.kubectlRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	args := parseCommandArgs(req.Command)
	if len(args) == 0 {
		c.JSON(http.StatusOK, gin.H{"error": "empty command"})
		return
	}

	output, cmdStr := routeCommand(ctx, client, args)
	c.JSON(http.StatusOK, gin.H{"output": output, "command": cmdStr})
}

// routeCommand 将 kubectl 风格的命令参数路由到 client-go 方法，无 kubectl 二进制依赖
func routeCommand(ctx context.Context, client *kubectl.Client, args []string) (string, string) {
	cmdStr := "kubectl " + strings.Join(args, " ")
	verb := args[0]
	switch verb {
	case "get":
		if len(args) < 2 {
			return "Usage: get <resource> [-A|-n namespace]", cmdStr
		}
		resource := args[1]
		ns, allNs := parseNS(args[2:])
		switch resource {
		case "pods", "pod":
			if allNs {
				ns = ""
			}
			list, err := client.ListPods(ctx, ns)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			return formatPodTable(list), cmdStr
		case "nodes", "node", "no":
			list, err := client.ListNodes(ctx)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			return formatNodeTable(list), cmdStr
		case "services", "service", "svc":
			if allNs {
				ns = ""
			}
			list, err := client.ListServices(ctx, ns)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			return formatSvcTable(list), cmdStr
		case "secrets", "secret":
			if allNs {
				ns = ""
			}
			list, err := client.ListSecrets(ctx, ns)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			return formatSecretTable(list), cmdStr
		case "namespaces", "namespace", "ns":
			list, err := client.ListNamespaces(ctx)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			return formatNSTable(list), cmdStr
		case "deployments", "deployment", "deploy":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, d := range list.Items {
				var image string
				if len(d.Spec.Template.Spec.Containers) > 0 {
					image = d.Spec.Template.Spec.Containers[0].Image
				}
				replicas := int32(0)
				if d.Spec.Replicas != nil {
					replicas = *d.Spec.Replicas
				}
				fmt.Fprintf(&sb, "%s/%s replicas=%d ready=%d %s\n", d.Namespace, d.Name, replicas, d.Status.ReadyReplicas, image)
			}
			return sb.String(), cmdStr
		case "daemonsets", "daemonset", "ds":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, ds := range list.Items {
				fmt.Fprintf(&sb, "%s/%s desired=%d ready=%d\n", ds.Namespace, ds.Name, ds.Status.DesiredNumberScheduled, ds.Status.NumberReady)
			}
			return sb.String(), cmdStr
		case "statefulsets", "statefulset", "sts":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, sts := range list.Items {
				replicas := int32(0)
				if sts.Spec.Replicas != nil {
					replicas = *sts.Spec.Replicas
				}
				fmt.Fprintf(&sb, "%s/%s replicas=%d ready=%d\n", sts.Namespace, sts.Name, replicas, sts.Status.ReadyReplicas)
			}
			return sb.String(), cmdStr
		case "cronjobs", "cronjob", "cj":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, cj := range list.Items {
				fmt.Fprintf(&sb, "%s/%s schedule=%s suspend=%v\n", cj.Namespace, cj.Name, cj.Spec.Schedule, valueOrFalse(cj.Spec.Suspend))
			}
			return sb.String(), cmdStr
		case "ingresses", "ingress", "ing":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, ing := range list.Items {
				fmt.Fprintf(&sb, "%s/%s rules=%d\n", ing.Namespace, ing.Name, len(ing.Spec.Rules))
			}
			return sb.String(), cmdStr
		case "networkpolicies", "networkpolicy", "netpol":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, netpol := range list.Items {
				fmt.Fprintf(&sb, "%s/%s ingress=%d egress=%d\n", netpol.Namespace, netpol.Name, len(netpol.Spec.Ingress), len(netpol.Spec.Egress))
			}
			return sb.String(), cmdStr
		case "serviceaccounts", "serviceaccount", "sa":
			if allNs {
				ns = ""
			}
			list, err := client.ListServiceAccounts(ctx, ns)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, sa := range list.Items {
				secrets := make([]string, len(sa.Secrets))
				for i, s := range sa.Secrets {
					secrets[i] = s.Name
				}
				fmt.Fprintf(&sb, "%s/%s secrets=%v\n", sa.Namespace, sa.Name, secrets)
			}
			return sb.String(), cmdStr
		case "clusterrolebindings", "clusterrolebinding", "crb":
			list, err := client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, crb := range list.Items {
				subjects := make([]string, 0, len(crb.Subjects))
				for _, subject := range crb.Subjects {
					subjects = append(subjects, subject.Kind+":"+subject.Name)
				}
				fmt.Fprintf(&sb, "%s role=%s subjects=%v\n", crb.Name, crb.RoleRef.Name, subjects)
			}
			return sb.String(), cmdStr
		case "configmaps", "configmap", "cm":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, cm := range list.Items {
				fmt.Fprintf(&sb, "%s/%s keys=%d\n", cm.Namespace, cm.Name, len(cm.Data)+len(cm.BinaryData))
			}
			return sb.String(), cmdStr
		case "persistentvolumeclaims", "persistentvolumeclaim", "pvc":
			if allNs {
				ns = ""
			}
			list, err := client.Clientset.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, pvc := range list.Items {
				fmt.Fprintf(&sb, "%s/%s status=%s volume=%s\n", pvc.Namespace, pvc.Name, pvc.Status.Phase, pvc.Spec.VolumeName)
			}
			return sb.String(), cmdStr
		case "persistentvolumes", "persistentvolume", "pv":
			list, err := client.Clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			var sb strings.Builder
			for _, pv := range list.Items {
				claim := "-"
				if pv.Spec.ClaimRef != nil {
					claim = pv.Spec.ClaimRef.Namespace + "/" + pv.Spec.ClaimRef.Name
				}
				fmt.Fprintf(&sb, "%s status=%s claim=%s\n", pv.Name, pv.Status.Phase, claim)
			}
			return sb.String(), cmdStr
		default:
			return "Unsupported resource: " + resource + " (supported: pods/nodes/services/secrets/deployments/daemonsets/statefulsets/cronjobs/ingresses/networkpolicies/pvc/pv/sa/namespaces/configmaps/crb). Use the dedicated buttons for structured output.", cmdStr
		}
	case "cluster-info":
		v, err := client.ServerVersion()
		if err != nil {
			return "Error: " + err.Error(), cmdStr
		}
		return "Kubernetes " + v, cmdStr
	case "auth":
		if len(args) >= 2 && args[1] == "can-i" {
			if len(args) >= 3 && args[2] == "--list" {
				return formatCanIList(ctx, client), cmdStr
			}

			ns, _ := parseNS(args[2:])
			filtered := make([]string, 0, len(args)-2)
			skipNext := false
			for _, arg := range args[2:] {
				if skipNext {
					skipNext = false
					continue
				}
				if arg == "-n" || arg == "--namespace" {
					skipNext = true
					continue
				}
				if arg == "-A" || arg == "--all-namespaces" {
					continue
				}
				filtered = append(filtered, arg)
			}

			if len(filtered) == 0 {
				ok, err := client.CheckSelfPermissions(ctx, "", "*", "*")
				if err != nil {
					return "Error: " + err.Error(), cmdStr
				}
				if ok {
					return "can-i *:* = yes (cluster-admin)", cmdStr
				}
				return "can-i *:* = no", cmdStr
			}

			verb := filtered[0]
			resource := "*"
			if len(filtered) >= 2 {
				resource = filtered[1]
			}
			effectiveNS := authCanINamespaceForResource(ns, resource)
			ok, err := client.CheckSelfPermissions(ctx, effectiveNS, verb, resource)
			if err != nil {
				return "Error: " + err.Error(), cmdStr
			}
			scope := resource
			if effectiveNS != "" && resource != "*" {
				scope += " in namespace " + effectiveNS
			}
			if ok {
				return fmt.Sprintf("yes: can %s %s", verb, scope), cmdStr
			}
			return fmt.Sprintf("no: cannot %s %s", verb, scope), cmdStr
		}
		return "Only 'auth can-i' is supported via client-go. Use Auth Can-I button for full RBAC check.", cmdStr
	default:
		return fmt.Sprintf("Cross-platform mode: kubectl binary not required. '%s' is not supported via client-go. Use the dedicated UI buttons for:\n  get pods/nodes/services/secrets/deployments/daemonsets/statefulsets/ingresses/networkpolicies/pvc/pv/sa/namespaces\n  cluster-info\n  auth can-i", verb), cmdStr
	}
}

func parseNS(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == "-A" || args[i] == "--all-namespaces" {
			return "", true
		}
		if (args[i] == "-n" || args[i] == "--namespace") && i+1 < len(args) {
			return args[i+1], false
		}
	}
	return "default", false
}

func formatCanIList(ctx context.Context, client *kubectl.Client) string {
	var sb strings.Builder
	for _, resource := range authCanIResourceSet {
		allowed := make([]string, 0)
		for _, verb := range authCanIVerbs {
			ok, _ := client.CheckSelfPermissions(ctx, "", verb, resource)
			if ok {
				allowed = append(allowed, verb)
			}
		}
		fmt.Fprintf(&sb, "%s: %s\n", resource, strings.Join(allowed, ", "))
	}
	if ok, err := client.CheckSelfPermissions(ctx, "", "*", "*"); err == nil {
		fmt.Fprintf(&sb, "cluster-admin: %v\n", ok)
	}
	return sb.String()
}

func authCanINamespaceForResource(namespace, resource string) string {
	if isClusterScopedResourceAlias(resource) {
		return ""
	}
	return namespace
}

func formatPodTable(list *corev1.PodList) string {
	var sb strings.Builder
	for _, p := range list.Items {
		fmt.Fprintf(&sb, "%s/%s %s node=%s ip=%s\n", p.Namespace, p.Name, p.Status.Phase, p.Spec.NodeName, p.Status.PodIP)
	}
	return sb.String()
}
func formatNodeTable(list *corev1.NodeList) string {
	var sb strings.Builder
	for _, n := range list.Items {
		var ip string
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" {
				ip = a.Address
			}
		}
		fmt.Fprintf(&sb, "%s Ready=%v ip=%s os=%s\n", n.Name, isNodeReady(&n), ip, n.Status.NodeInfo.OSImage)
	}
	return sb.String()
}
func formatSvcTable(list *corev1.ServiceList) string {
	var sb strings.Builder
	for _, s := range list.Items {
		fmt.Fprintf(&sb, "%s/%s %s clusterIP=%s\n", s.Namespace, s.Name, s.Spec.Type, s.Spec.ClusterIP)
	}
	return sb.String()
}
func formatSecretTable(list *corev1.SecretList) string {
	var sb strings.Builder
	for _, s := range list.Items {
		fmt.Fprintf(&sb, "%s/%s type=%s keys=%d\n", s.Namespace, s.Name, s.Type, len(s.Data))
	}
	return sb.String()
}
func formatNSTable(list *corev1.NamespaceList) string {
	var sb strings.Builder
	for _, ns := range list.Items {
		fmt.Fprintf(&sb, "%s %s\n", ns.Name, ns.Status.Phase)
	}
	return sb.String()
}
func isNodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (h *KubectlHandler) Apply(c *gin.Context) {
	var req struct {
		kubectlRequest
		YAML string `json:"yaml" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.buildClient(&req.kubectlRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	output, err := client.ApplyYAML(ctx, req.YAML)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": output, "command": "kubectl apply -f <yaml> (via client-go)"})
}

func (h *KubectlHandler) Delete(c *gin.Context) {
	var req struct {
		kubectlRequest
		YAML      string `json:"yaml"`
		Resource  string `json:"resource"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.YAML) == "" && (strings.TrimSpace(req.Resource) == "" || strings.TrimSpace(req.Name) == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide yaml or resource/name"})
		return
	}
	client, err := h.buildClient(&req.kubectlRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if strings.TrimSpace(req.YAML) != "" {
		output, err := client.DeleteYAML(ctx, req.YAML)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err.Error(), "output": output})
			return
		}
		c.JSON(http.StatusOK, gin.H{"output": output, "command": "kubectl delete -f <yaml> (via client-go)"})
		return
	}
	if req.Namespace == "" && !isClusterScopedResourceAlias(req.Resource) {
		req.Namespace = "default"
	}
	err = client.DeleteResource(ctx, req.Resource, req.Name, req.Namespace)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"output":  formatDeleteMessage(req.Resource, req.Name, req.Namespace),
		"command": formatDeleteCommand(req.Resource, req.Name, req.Namespace),
	})
}

func isClusterScopedResourceAlias(resource string) bool {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "namespace", "namespaces", "ns", "clusterrole", "clusterroles", "cr", "clusterrolebinding", "clusterrolebindings", "crb":
		return true
	default:
		return false
	}
}

func formatDeleteMessage(resource, name, namespace string) string {
	if namespace == "" {
		return fmt.Sprintf("deleted %s/%s", resource, name)
	}
	return fmt.Sprintf("deleted %s/%s in %s", resource, name, namespace)
}

func formatDeleteCommand(resource, name, namespace string) string {
	if namespace == "" {
		return fmt.Sprintf("kubectl delete %s %s", resource, name)
	}
	return fmt.Sprintf("kubectl delete %s %s -n %s", resource, name, namespace)
}

func valueOrFalse(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

func parseCommandArgs(cmd string) []string {
	args := []string{}
	current := ""
	inQuote := false
	quoteChar := byte(0)
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current += string(c)
			}
		} else if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = c
		} else if c == ' ' {
			if current != "" {
				args = append(args, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		args = append(args, current)
	}
	return args
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
