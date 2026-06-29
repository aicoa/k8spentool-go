package util

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
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
	return ScanPorts(host, K8sPorts, timeoutSec)
}

func ScanPorts(host string, ports []PortInfo, timeoutSec int) *PortScanResult {
	result := &PortScanResult{
		Host:    host,
		Timeout: timeoutSec,
		Total:   len(ports),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, pi := range ports {
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
	case <-time.After(time.Duration(timeoutSec*len(ports)+5) * time.Second):
		fmt.Printf("[WARN] Port scan timed out after %ds\n", timeoutSec*len(ports)+5)
	}

	sort.Slice(result.Open, func(i, j int) bool { return result.Open[i].Port < result.Open[j].Port })
	sort.Ints(result.Closed)
	return result
}

func ParsePortSpec(spec string) ([]PortInfo, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	known := make(map[int]string, len(K8sPorts))
	for _, port := range K8sPorts {
		known[port.Port] = port.Service
	}
	seen := make(map[int]bool)
	result := make([]PortInfo, 0)
	addPort := func(port int) {
		if port <= 0 || port > 65535 || seen[port] {
			return
		}
		seen[port] = true
		service := known[port]
		if service == "" {
			service = "Custom"
		}
		result = append(result, PortInfo{Port: port, Service: service})
	}
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", token)
			}
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", token)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end: %s", token)
			}
			if end < start {
				return nil, fmt.Errorf("invalid port range: %s", token)
			}
			for port := start; port <= end; port++ {
				addPort(port)
			}
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", token)
		}
		addPort(port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Port < result[j].Port })
	return result, nil
}
