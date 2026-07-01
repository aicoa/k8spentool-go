package kubectl

import (
	"net"
	"strings"
)

// APIServerURL normalizes a target host into a Kubernetes API server URL.
func APIServerURL(targetHost string) string {
	host := strings.TrimSpace(targetHost)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "https://") || strings.HasPrefix(host, "http://") {
		return strings.TrimRight(host, "/")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "https://" + host
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		return "https://[" + host + "]:6443"
	}
	return "https://" + host + ":6443"
}

// NewTargetClient builds an authenticated or anonymous client for a target host.
func NewTargetClient(targetHost, token, username, password string, skipTLS bool) (*Client, error) {
	server := APIServerURL(targetHost)
	if token != "" {
		return NewClient(server, token, skipTLS)
	}
	if username != "" {
		return NewClientWithUserPass(server, username, password, skipTLS)
	}
	return NewClient(server, "", skipTLS)
}
