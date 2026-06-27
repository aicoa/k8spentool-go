package util

import (
	"fmt"
	"sync"
	"time"
)

var K8sPorts = []PortInfo{
	{6443, "APIServer (secure HTTPS)"},
	{8080, "APIServer (insecure HTTP)"},
	{10250, "Kubelet API"},
	{10255, "Kubelet (read-only)"},
	{2379, "Etcd Client"},
	{2380, "Etcd Peer"},
	{443, "Dashboard / API Proxy"},
	{8443, "Dashboard (alt)"},
	{10251, "kube-scheduler"},
	{10252, "kube-controller-manager"},
	{10256, "kube-proxy healthz"},
	{2375, "Docker API (unencrypted)"},
	{4149, "cAdvisor"},
	{30000, "NodePort range start"},
	{32767, "NodePort range end"},
	{8001, "kubectl proxy"},
}

type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

type PortScanResult struct {
	Host    string     `json:"host"`
	Open    []PortInfo `json:"open_ports"`
	Closed  []int      `json:"closed_ports"`
	Total   int        `json:"total_scanned"`
	Timeout int        `json:"timeout_sec"`
}

func QuickPortScan(host string, timeoutSec int) *PortScanResult {
	result := &PortScanResult{
		Host:    host,
		Timeout: timeoutSec,
		Total:   len(K8sPorts),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, pi := range K8sPorts {
		wg.Add(1)
		go func(p PortInfo) {
			defer wg.Done()
			if IsPortOpen(host, p.Port, timeoutSec) {
				mu.Lock()
				result.Open = append(result.Open, p)
				mu.Unlock()
			} else {
				mu.Lock()
				result.Closed = append(result.Closed, p.Port)
				mu.Unlock()
			}
		}(pi)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(timeoutSec*len(K8sPorts)+5) * time.Second):
		fmt.Printf("[WARN] Port scan timed out after %ds\n", timeoutSec*len(K8sPorts)+5)
	}

	return result
}
