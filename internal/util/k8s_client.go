package util

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// BuildHTTPTransport creates an http.Transport with TLS settings and optional SOCKS5 proxy.
func BuildHTTPTransport(skipVerify bool, timeoutSec int) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	// Inject SOCKS5 proxy if configured
	if dialCtx := ProxyDialContext(); dialCtx != nil {
		tr.DialContext = dialCtx
		tr.Proxy = nil // disable HTTP_PROXY to avoid conflicts
	}
	return tr
}

// BuildHTTPClient creates an http.Client with proxy-aware transport.
func BuildHTTPClient(skipVerify bool, timeoutSec int) *http.Client {
	return &http.Client{
		Transport: BuildHTTPTransport(skipVerify, timeoutSec),
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
}

func SendRequest(url, method, token string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("User-Agent", "K8sPenTool-ng/2.0")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := BuildHTTPClient(skipVerify, timeoutSec)

	resp, err := client.Do(req)
	if err != nil {
		if skipVerify && strings.Contains(err.Error(), "tls") {
			return 0, nil, fmt.Errorf("TLS error: %w", err)
		}
		return 0, nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read body failed: %w", err)
	}
	return resp.StatusCode, body, nil
}

func SendPost(url, body, contentType, token string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	req, err := http.NewRequest("POST", url, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("User-Agent", "K8sPenTool-ng/2.0")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := BuildHTTPClient(skipVerify, timeoutSec)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read body failed: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func IsPortOpen(host string, port int, timeoutSec int) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func FormatResponse(statusCode int, body []byte) string {
	if len(body) == 0 {
		return fmt.Sprintf("[HTTP %d] (no body)", statusCode)
	}
	return fmt.Sprintf("[HTTP %d]\n%s", statusCode, string(body))
}
