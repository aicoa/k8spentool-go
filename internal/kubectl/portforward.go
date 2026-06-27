package kubectl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForward tunnels a local port to a pod port (equivalent to kubectl port-forward pod localPort:podPort)
// Returns a stop channel to close the tunnel
func (c *Client) PortForward(ctx context.Context, namespace, podName string, localPort, podPort int) (chan struct{}, error) {
	stopCh := make(chan struct{})
	readyCh := make(chan struct{})

	// Build port-forward URL
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(c.config)
	if err != nil {
		return nil, fmt.Errorf("create SPDY round tripper: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())

	ports := []string{fmt.Sprintf("%d:%d", localPort, podPort)}
	pf, err := portforward.New(dialer, ports, stopCh, readyCh, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create port forwarder: %w", err)
	}

	// Start forwarding in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- pf.ForwardPorts()
	}()

	// Wait for ready or error
	select {
	case <-readyCh:
		return stopCh, nil
	case err := <-errCh:
		close(stopCh)
		return nil, fmt.Errorf("port forward failed: %w", err)
	case <-time.After(5 * time.Second):
		close(stopCh)
		return nil, fmt.Errorf("port forward timeout waiting for ready")
	case <-ctx.Done():
		close(stopCh)
		return nil, ctx.Err()
	}
}

// ForwardPodPort opens a tunnel from local port to pod port (simpler API)
// localPort: port on local machine (e.g. 8080)
// podPort: port in the pod (e.g. 80)
// namespace + podName: target pod
// Returns a stop function to close the tunnel
func (c *Client) ForwardPodPort(namespace, podName string, localPort, podPort int) (func(), error) {
	ctx := context.Background()
	stopCh, err := c.PortForward(ctx, namespace, podName, localPort, podPort)
	if err != nil {
		return nil, err
	}

	stopFunc := func() {
		close(stopCh)
	}

	return stopFunc, nil
}

// GetPodForwardURL builds a kubectl-style port-forward command hint for the user
func GetPodForwardURL(podName, namespace string, podPort int) string {
	return fmt.Sprintf("kubectl port-forward -n %s pod/%s :%d", namespace, podName, podPort)
}

// BuildSPDYURL returns the raw SPDY websocket URL for port-forwarding (for debugging)
func (c *Client) BuildSPDYURL(namespace, podName string) (*url.URL, error) {
	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"/bin/sh"},
			Stdin:   true,
			Stdout:  true,
			TTY:     true,
		}, nil)

	return req.URL(), nil
}
