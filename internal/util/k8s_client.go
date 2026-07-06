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

func applyAuthHeaders(req *http.Request, token, username, password string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		return
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
}

func SendRequest(url, method, token string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	return SendRequestWithAuth(url, method, token, "", "", timeoutSec, skipVerify)
}

func SendRequestWithAuth(url, method, token, username, password string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	return SendRequestWithBodyWithAuth(url, method, "", "", token, username, password, timeoutSec, skipVerify)
}

func newRequestWithAuth(method, url, requestBody, contentType, token, username, password string) (*http.Request, error) {
	var reader io.Reader
	if requestBody != "" {
		reader = strings.NewReader(requestBody)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("User-Agent", "K8sPenTool-ng/2.0")
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else if requestBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	applyAuthHeaders(req, token, username, password)
	return req, nil
}

func SendRequestWithBodyWithAuth(url, method, requestBody, contentType, token, username, password string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	req, err := newRequestWithAuth(method, url, requestBody, contentType, token, username, password)
	if err != nil {
		return 0, nil, err
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read body failed: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func SendPost(url, body, contentType, token string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	return SendPostWithAuth(url, body, contentType, token, "", "", timeoutSec, skipVerify)
}

func SendPostWithAuth(url, body, contentType, token, username, password string, timeoutSec int, skipVerify bool) (int, []byte, error) {
	if contentType == "" {
		contentType = "application/json"
	}
	return SendRequestWithBodyWithAuth(url, http.MethodPost, body, contentType, token, username, password, timeoutSec, skipVerify)
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
