package util

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var kubectlPath string

func init() {
	if p, err := findSystemKubectl(); err == nil {
		kubectlPath = p
	}
}

func SetKubectlPath(path string) {
	if path != "" {
		kubectlPath = path
	}
}

func GetKubectlPath() string {
	if kubectlPath == "" {
		return "kubectl"
	}
	return kubectlPath
}

func findSystemKubectl() (string, error) {
	p, err := exec.LookPath("kubectl")
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

type KubectlConfig struct {
	Server          string
	Token           string
	Username        string
	Password        string
	SkipTLS         bool
	KubeconfigPath  string
	TimeoutSec      int
}

func (c *KubectlConfig) buildArgs(args ...string) []string {
	cmdArgs := make([]string, 0, len(args)+10)
	if c.Server != "" {
		cmdArgs = append(cmdArgs, "--server="+c.Server)
	}
	if c.Token != "" {
		cmdArgs = append(cmdArgs, "--token="+c.Token)
	} else if c.Username != "" {
		cmdArgs = append(cmdArgs, "--username="+c.Username)
		cmdArgs = append(cmdArgs, "--password="+c.Password)
	}
	if c.SkipTLS {
		cmdArgs = append(cmdArgs, "--insecure-skip-tls-verify=true")
	}
	if c.KubeconfigPath != "" {
		cmdArgs = append(cmdArgs, "--kubeconfig="+c.KubeconfigPath)
	}
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

func ExecKubectl(cfg *KubectlConfig, args ...string) (string, error) {
	cmdArgs := cfg.buildArgs(args...)
	return runKubectl(cfg.TimeoutSec, cmdArgs...)
}

func ExecKubectlRaw(timeoutSec int, args ...string) (string, error) {
	return runKubectl(timeoutSec, args...)
}

var (
	lastCommandMu sync.Mutex
	LastCommand   string
)

func setLastCommand(cmd string) {
	lastCommandMu.Lock()
	LastCommand = cmd
	lastCommandMu.Unlock()
}

func runKubectl(timeoutSec int, args ...string) (string, error) {
	exe := GetKubectlPath()

	cmdStr := "kubectl"
	for _, a := range args {
		if strings.HasPrefix(a, "--token=") && len(a) > 28 {
			cmdStr += " --token=" + a[8:28] + "..."
		} else {
			cmdStr += " " + a
		}
	}
	setLastCommand(cmdStr)

	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	ctx := exec.Command(exe, args...)
	ctx.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	ctx.Stdout = &stdout
	ctx.Stderr = &stderr
	ctx.Stdin = strings.NewReader("")

	if err := ctx.Start(); err != nil {
		return "", fmt.Errorf("kubectl start failed: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- ctx.Wait() }()

	select {
	case err := <-done:
		output := stdout.String()
		if stderr.Len() > 0 {
			output += stderr.String()
		}
		if err != nil {
			return fmt.Sprintf("[Exit code: %d]\n%s", ctx.ProcessState.ExitCode(), output), nil
		}
		return output, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		ctx.Process.Kill()
		output := stdout.String()
		if stderr.Len() > 0 {
			output += stderr.String()
		}
		return output + "\n[!] Command timed out\n", nil
	}
}

func SaveKubeconfig(content string) (string, error) {
	f, err := os.CreateTemp("", "k8spen_kubeconfig_*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func SaveYAML(content string) (string, error) {
	f, err := os.CreateTemp("", "k8spen_yaml_*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}
