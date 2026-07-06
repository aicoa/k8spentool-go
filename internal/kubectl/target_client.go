package kubectl

import (
	"net"
	"net/url"
	"strconv"
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

// TargetHostname strips any scheme or port from a target and returns the host name only.
func TargetHostname(targetHost string) string {
	host := strings.TrimSpace(targetHost)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil {
			if parsed.Hostname() != "" {
				return parsed.Hostname()
			}
			host = parsed.Host
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(parsedHost, "[]")
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		return host
	}
	return strings.Trim(host, "[]")
}

// TargetServiceURL builds a scheme://host:port/path URL for non-APIServer ports such as kubelet and etcd.
func TargetServiceURL(targetHost, scheme string, port int, path string) string {
	host := TargetHostname(targetHost)
	if host == "" {
		return ""
	}
	base := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
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
