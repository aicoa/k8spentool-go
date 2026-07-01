package util

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestProxyConfigPersistsToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	t.Setenv("K8SPEN_PROXY_CONFIG_PATH", path)

	proxyCfg = nil
	proxyCached = nil
	proxyOnce = sync.Once{}

	SetProxyConfig(&ProxyConfig{
		Enabled:  true,
		Host:     "127.0.0.1",
		Port:     1080,
		Username: "user",
		Password: "pass",
	})

	proxyCfg = nil
	proxyCached = nil
	proxyOnce = sync.Once{}

	cfg := GetProxyConfig()
	if cfg == nil {
		t.Fatalf("expected proxy config to reload from disk")
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 1080 || cfg.Username != "user" {
		t.Fatalf("unexpected proxy config: %#v", cfg)
	}

	ClearProxyConfig()
	proxyCfg = nil
	proxyCached = nil
	proxyOnce = sync.Once{}
	if cfg := GetProxyConfig(); cfg != nil {
		t.Fatalf("expected proxy config file to be removed, got %#v", cfg)
	}
}
