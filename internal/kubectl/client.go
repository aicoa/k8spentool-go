package kubectl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/trymonoly/K8sPenTool-ng/internal/util"
)

type Client struct {
	Clientset *kubernetes.Clientset
	config    *rest.Config
	mode      string
}

// applyProxyToConfig injects the global SOCKS5 proxy dialer into a rest.Config.
// Does nothing if no proxy is configured.
func applyProxyToConfig(cfg *rest.Config) {
	dialCtx := util.ProxyDialContext()
	if dialCtx == nil {
		return
	}
	// WrapTransport replaces the underlying http.Transport with one that
	// routes all TCP connections through the SOCKS5 proxy.
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if tr, ok := rt.(*http.Transport); ok {
			newTr := tr.Clone()
			newTr.DialContext = dialCtx
			newTr.Proxy = nil // disable HTTP_PROXY to avoid conflicts
			return newTr
		}
		return rt
	}
}

func NewClient(server, token string, skipTLS bool) (*Client, error) {
	if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://") {
		server = "https://" + server
	}
	cfg := &rest.Config{
		Host:        server,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: skipTLS,
		},
	}
	applyProxyToConfig(cfg)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Client{Clientset: clientset, config: cfg, mode: "token"}, nil
}

func NewClientWithUserPass(server, username, password string, skipTLS bool) (*Client, error) {
	if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://") {
		server = "https://" + server
	}
	cfg := &rest.Config{
		Host:     server,
		Username: username,
		Password: password,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: skipTLS,
		},
	}
	applyProxyToConfig(cfg)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Client{Clientset: clientset, config: cfg, mode: "userpass"}, nil
}

func NewClientFromKubeconfig(kubeconfigPath string) (*Client, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{
		ExplicitPath: kubeconfigPath,
	}
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	cfg, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	applyProxyToConfig(cfg)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Client{Clientset: clientset, config: cfg, mode: "kubeconfig"}, nil
}

func NewClientInCluster() (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	applyProxyToConfig(cfg)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Client{Clientset: clientset, config: cfg, mode: "token"}, nil
}

func (c *Client) ListPods(ctx context.Context, namespace string) (*corev1.PodList, error) {
	if namespace == "" {
		return c.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	}
	return c.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return c.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) DeletePod(ctx context.Context, namespace, name string) error {
	return c.Clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (c *Client) ExecInPod(ctx context.Context, namespace, pod, container string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("executor: %w", err)
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    false,
	})
}

func (c *Client) ListSecrets(ctx context.Context, namespace string) (*corev1.SecretList, error) {
	if namespace == "" {
		return c.Clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	}
	return c.Clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) ListServices(ctx context.Context, namespace string) (*corev1.ServiceList, error) {
	if namespace == "" {
		return c.Clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	}
	return c.Clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) ListNodes(ctx context.Context) (*corev1.NodeList, error) {
	return c.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
}

func (c *Client) ListServiceAccounts(ctx context.Context, namespace string) (*corev1.ServiceAccountList, error) {
	if namespace == "" {
		return c.Clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	}
	return c.Clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) CreateServiceAccount(ctx context.Context, namespace string, sa *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
	return c.Clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
}

func (c *Client) ListEndpoints(ctx context.Context, namespace string) (*corev1.EndpointsList, error) {
	if namespace == "" {
		return c.Clientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	}
	return c.Clientset.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) ListNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	return c.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
}

// CheckSelfPermissions checks if the current SA has specific permissions
func (c *Client) CheckSelfPermissions(ctx context.Context, namespace, verb, resource string) (bool, error) {
	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Resource:  resource,
			},
		},
	}
	result, err := c.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return result.Status.Allowed, nil
}

func (c *Client) RawRequest(ctx context.Context, method, path string) ([]byte, error) {
	req := c.Clientset.CoreV1().RESTClient().Verb(method).RequestURI(path)
	return req.DoRaw(ctx)
}

func (c *Client) DiscoverResources(ctx context.Context) ([]*metav1.APIResourceList, error) {
	return c.Clientset.Discovery().ServerPreferredResources()
}

func (c *Client) ServerVersion() (string, error) {
	info, err := c.Clientset.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	return info.GitVersion, nil
}

type PodExecResult struct {
	Stdout string
	Stderr string
}

func (c *Client) ExecInPodResult(ctx context.Context, namespace, pod, container string, command []string) (*PodExecResult, error) {
	var stdout, stderr strings.Builder
	err := c.ExecInPod(ctx, namespace, pod, container, command, nil, &stdout, &stderr)
	return &PodExecResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

// CreateClusterRoleBinding creates a ClusterRoleBinding
func (c *Client) CreateClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) (*rbacv1.ClusterRoleBinding, error) {
	return c.Clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
}


// DeleteResource deletes a named resource by kind.
func (c *Client) DeleteResource(ctx context.Context, kind, name, namespace string) error {
	switch strings.ToLower(kind) {
	case "pod", "pods":
		return c.Clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "service", "services", "svc":
		return c.Clientset.CoreV1().Services(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "deployment", "deployments", "deploy":
		return c.Clientset.AppsV1().Deployments(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "daemonset", "daemonsets", "ds":
		return c.Clientset.AppsV1().DaemonSets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "cronjob", "cronjobs", "cj":
		return c.Clientset.BatchV1().CronJobs(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "secret", "secrets":
		return c.Clientset.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "serviceaccount", "serviceaccounts", "sa":
		return c.Clientset.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	default:
		return fmt.Errorf("unsupported resource kind: %s (supported: pod/service/deployment/daemonset/cronjob/secret/sa)", kind)
	}
}

