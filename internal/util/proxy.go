package util

import (
	"context"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// ProxyConfig stores SOCKS5 proxy configuration.
type ProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

var (
	proxyCfg   *ProxyConfig
	proxyMu    sync.RWMutex
	proxyCached proxy.Dialer
)

// GetProxyConfig returns the current global proxy configuration.
func GetProxyConfig() *ProxyConfig {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	if proxyCfg == nil {
		return nil
	}
	// Return a copy to avoid race conditions
	cp := *proxyCfg
	return &cp
}

// SetProxyConfig sets the global proxy configuration.
func SetProxyConfig(cfg *ProxyConfig) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if cfg == nil {
		proxyCfg = nil
		proxyCached = nil
		return
	}
	proxyCfg = cfg
	proxyCached = nil // invalidate cache
}

// ClearProxyConfig disables and clears the proxy configuration.
func ClearProxyConfig() {
	SetProxyConfig(nil)
}

// IsProxyEnabled returns true if a proxy is configured and enabled.
func IsProxyEnabled() bool {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return proxyCfg != nil && proxyCfg.Enabled
}

// Address returns the proxy address in host:port format.
func (c *ProxyConfig) Address() string {
	if c == nil {
		return ""
	}
	return net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
}

// getProxyDialer creates or returns a cached SOCKS5 dialer.
func getProxyDialer() (proxy.Dialer, error) {
	proxyMu.RLock()
	if proxyCached != nil {
		d := proxyCached
		proxyMu.RUnlock()
		return d, nil
	}
	proxyMu.RUnlock()

	proxyMu.Lock()
	defer proxyMu.Unlock()

	// Double-check after acquiring write lock
	if proxyCached != nil {
		return proxyCached, nil
	}

	if proxyCfg == nil || !proxyCfg.Enabled {
		return nil, fmt.Errorf("proxy not configured")
	}

	var auth *proxy.Auth
	if proxyCfg.Username != "" {
		auth = &proxy.Auth{
			User:     proxyCfg.Username,
			Password: proxyCfg.Password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", proxyCfg.Address(), auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	proxyCached = dialer
	return dialer, nil
}

// ProxyDialContext returns a DialContext function that routes through the
// configured SOCKS5 proxy. Returns nil if no proxy is configured, so callers
// can fall back to direct connections.
func ProxyDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !IsProxyEnabled() {
		return nil
	}
	dialer, err := getProxyDialer()
	if err != nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// golang.org/x/net/proxy.Dialer.Dial does not accept context,
		// but the connection will still work. For proper context support,
		// we'd use a custom dialer with net.Dialer.Control.
		return dialer.Dial(network, addr)
	}
}
