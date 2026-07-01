package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/trymonoly/K8sPenTool-ng/internal/api/handler"
	"github.com/trymonoly/K8sPenTool-ng/internal/api/ws"
	"sigs.k8s.io/yaml"
)

func resolveExistingPath(candidates ...string) string {
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func openAPISpecPath() string {
	return resolveExistingPath(
		"openapi/openapi.yaml",
		filepath.Join("..", "..", "openapi", "openapi.yaml"),
	)
}

func swaggerAssetsPath() string {
	return resolveExistingPath(
		"web/swagger",
		filepath.Join("..", "..", "web", "swagger"),
	)
}

func frontendIndexPath() string {
	return resolveExistingPath(
		"web/dist/index.html",
		filepath.Join("..", "..", "web", "dist", "index.html"),
	)
}

func SetupRouter(hub *ws.Hub) *gin.Engine {
	r := gin.Default()
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.Use(CORSMiddleware())
	r.Use(LoggerMiddleware())

	// Handlers
	targetH := handler.NewTargetHandler(hub)
	infoH := handler.NewInfoHandler()
	accessH := handler.NewAccessHandler()
	execH := handler.NewExecHandler()
	persistH := handler.NewPersistHandler()
	escapeH := handler.NewEscapeHandler()
	lateralH := handler.NewLateralHandler()
	kubectlH := handler.NewKubectlHandler()
	aiH := handler.NewAIHandler(targetH)
	cdkH := handler.NewCDKHandler()
	dashH := handler.NewDashboardHandler()

	// OpenAPI spec
	r.GET("/openapi.json", func(c *gin.Context) {
		body, err := os.ReadFile(openAPISpecPath())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		jsonBody, err := yaml.YAMLToJSON(body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", jsonBody)
	})
	r.GET("/openapi.yaml", func(c *gin.Context) {
		c.File(openAPISpecPath())
	})
	r.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger/")
	})
	r.Static("/swagger", swaggerAssetsPath())

	// WebSocket
	r.GET("/api/v1/ws", func(c *gin.Context) {
		hub.HandleWS(c.Writer, c.Request)
	})

	// Health
	r.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "2.0.0"})
	})

	v1 := r.Group("/api/v1")
	{
		// Target
		v1.POST("/targets", targetH.CreateTarget)
		v1.GET("/targets", targetH.ListTargets)
		v1.GET("/targets/:id", targetH.GetTarget)
		v1.DELETE("/targets/:id", targetH.DeleteTarget)
		v1.POST("/targets/:id/steps", targetH.RecordStep)

		// Proxy (SOCKS5)
		v1.GET("/proxy", targetH.GetProxyConfig)
		v1.POST("/proxy", targetH.SetProxyConfig)
		v1.DELETE("/proxy", targetH.ClearProxyConfig)

		// Info
		info := v1.Group("/info")
		{
			info.GET("/profiles", infoH.GetProfiles)
			info.POST("/profiles/:id/run", infoH.RunProfile)
			info.POST("/port-scan", infoH.PortScan)
			info.POST("/decode-capabilities", infoH.DecodeCapabilities)
			info.GET("/env-check-cmds", infoH.GetEnvCheckCmds)
			info.GET("/priv-check-cmds", infoH.GetPrivCheckCmds)
			info.GET("/sa-token-cmds", infoH.GetSATokenCmds)
			info.GET("/port-reference", infoH.GetPortReference)
		}

		// Access
		access := v1.Group("/access")
		{
			access.POST("/api-server", accessH.CheckAPIServer)
			access.POST("/api-server/insecure", accessH.CheckInsecurePort)
			access.POST("/api-server/request", accessH.SendCustomRequest)
			access.POST("/kubelet", accessH.CheckKubelet)
			access.POST("/kubelet/exec", accessH.KubeletExec)
			access.POST("/etcd/check", accessH.CheckEtcd)
			access.POST("/etcd/keys", accessH.EtcdGetKeys)
			access.POST("/etcd/read", accessH.EtcdReadKey)
			access.POST("/etcd/v3/keys", accessH.EtcdV3GetKeys)
			access.POST("/etcd/v3/search-secrets", accessH.EtcdV3SearchSecrets)
			access.POST("/kubelet/inject-ssh", accessH.KubeletSSHInject)
			access.POST("/dashboard", accessH.CheckDashboard)
			access.POST("/kubeconfig/parse", accessH.ParseKubeconfig)
		}

		// Exec
		exec := v1.Group("/exec")
		{
			exec.POST("/api-server/list-pods", execH.APIListPods)
			exec.POST("/api-server/exec", execH.APIExecInPod)
			exec.POST("/api-server/enum-sa-tokens", execH.EnumSATokens)
			exec.POST("/kubelet/list-pods", execH.KubeletListPods)
			exec.POST("/kubelet/exec", execH.KubeletExec)
			exec.POST("/backdoor/generate-yaml", execH.GenerateBackdoorYAML)
			exec.POST("/rbac/check", execH.CheckRBAC)
			exec.POST("/reverse-shell/generate", execH.GenerateRevShell)
			exec.POST("/upload-file", execH.UploadFile)
			exec.POST("/port-forward", execH.PortForwardInfo)
		}

		// Persist
		persist := v1.Group("/persist")
		{
			persist.POST("/service-account", persistH.CreateAdminSA)
			persist.POST("/service-account/token", persistH.GetSAToken)
			persist.POST("/cronjob", persistH.GenerateCronJob)
			persist.POST("/daemonset", persistH.GenerateDaemonSet)
			persist.POST("/kubeconfig", persistH.GenerateKubeconfig)
			persist.POST("/host-crontab", persistH.GenerateHostPersistence)
		}

		// Escape
		escape := v1.Group("/escape")
		{
			escape.GET("/checks", escapeH.GetEscapeChecks)
			escape.POST("/privileged", escapeH.PrivilegedEscape)
			escape.POST("/mount", escapeH.MountEscape)
			escape.GET("/kernel-vulns", escapeH.KernelVulnerabilities)
		}

		// Lateral
		lateral := v1.Group("/lateral")
		{
			lateral.POST("/secrets", lateralH.ListSecrets)
			lateral.POST("/secrets/view", lateralH.ViewSecret)
			lateral.POST("/services", lateralH.ListServices)
			lateral.POST("/endpoints", lateralH.ListEndpoints)
			lateral.POST("/nodes", lateralH.ListNodes)
			lateral.POST("/network-policies", lateralH.ListNetworkPolicies)
			lateral.POST("/taints", lateralH.ShowTaints)
			lateral.POST("/taint-pod", lateralH.GenerateTaintPod)
		}

		// Kubectl
		kctl := v1.Group("/kubectl")
		{
			kctl.POST("/get-nodes", kubectlH.GetNodes)
			kctl.POST("/get-pods", kubectlH.GetPods)
			kctl.POST("/get-services", kubectlH.GetServices)
			kctl.POST("/get-secrets", kubectlH.GetSecrets)
			kctl.POST("/get-deployments", kubectlH.GetDeployments)
			kctl.POST("/cluster-info", kubectlH.ClusterInfo)
			kctl.POST("/auth-can-i", kubectlH.AuthCanI)
			kctl.POST("/get-sa", kubectlH.GetSA)
			kctl.POST("/get-crb", kubectlH.GetCRB)
			kctl.POST("/get-images", kubectlH.GetImages)
			kctl.POST("/apply", kubectlH.Apply)
			kctl.POST("/delete", kubectlH.Delete)
			kctl.POST("/exec", kubectlH.CustomCommand)
		}

		// AI
		ai := v1.Group("/ai")
		{
			ai.POST("/sessions", aiH.CreateSession)
			ai.GET("/sessions", aiH.ListSessions)
			ai.GET("/sessions/:id", aiH.GetSession)
			ai.POST("/sessions/:id/chat", aiH.Chat)
			ai.POST("/sessions/:id/plan", aiH.GeneratePlan)
			ai.GET("/sessions/:id/plan", aiH.GetPlan)
			ai.POST("/sessions/:id/approve", aiH.ApproveStep)
			ai.POST("/sessions/:id/stop", aiH.StopSession)
			ai.DELETE("/sessions/:id", aiH.DeleteSession)
			ai.GET("/config", aiH.GetConfig)
			ai.PUT("/config", aiH.UpdateConfig)
		}

		// CDK Tactics
		cdk := v1.Group("/cdk")
		{
			cdk.POST("/configmaps", cdkH.DumpConfigMaps)
			cdk.POST("/psp", cdkH.DumpPSP)
			cdk.POST("/docker-api", cdkH.CheckDockerAPI)
			cdk.POST("/shadow-apiserver", cdkH.ShadowAPIServer)
			cdk.POST("/clusterip-mitm", cdkH.ClusterIPMITM)
			cdk.POST("/escape-pod", cdkH.GenerateEscapePod)
			cdk.POST("/assess-escape", cdkH.AssessEscape)
		}

		// Dashboard Attack
		dashboard := v1.Group("/dashboard")
		{
			dashboard.POST("/discover", dashH.Discover)
			dashboard.POST("/probe", dashH.Probe)
			dashboard.POST("/extract-token", dashH.ExtractToken)
		}
	}

	// Serve frontend in production
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method == "GET" && c.Request.URL.Path != "" {
			c.File(frontendIndexPath())
		}
	})

	return r
}
