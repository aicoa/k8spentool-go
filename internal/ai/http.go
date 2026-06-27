package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func doHTTPRequest(ctx context.Context, method, url, apiKey string, body []byte) ([]byte, error) {
	return doHTTPRequestWithHeader(ctx, method, url, apiKey, body, nil)
}

func doHTTPRequestWithHeader(ctx context.Context, method, url, apiKey string, body []byte, extraHeaders map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("LLM API error %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}
