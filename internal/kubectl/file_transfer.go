package kubectl

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// UploadFile copies a local file to a pod (equivalent to kubectl cp /local/file pod:/remote/path)
// Uses tar + SPDY exec, same mechanism as kubectl cp
func (c *Client) UploadFile(ctx context.Context, namespace, podName, containerName, srcPath, destPath string) (string, error) {
	if containerName == "" {
		containerName = c.getDefaultContainer(ctx, namespace, podName)
		if containerName == "" {
			return "", fmt.Errorf("no container found in pod %s/%s", namespace, podName)
		}
	}

	// Read source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("read source file %s: %w", srcPath, err)
	}

	// Build tar archive
	fileName := filepath.Base(destPath)
	destDir := filepath.Dir(destPath)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{
		Name: fileName,
		Mode: 0755,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return "", fmt.Errorf("tar write header: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return "", fmt.Errorf("tar write data: %w", err)
	}
	tw.Close()

	// Exec tar -xmf - in the pod to extract
	execCmd := []string{"tar", "-xmf", "-", "-C", destDir}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   execCmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create SPDY executor: %w", err)
	}

	streamOpts := remotecommand.StreamOptions{
		Stdin:  &tarBuf,
		Stdout: stdout,
		Stderr: stderr,
	}

	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err = exec.StreamWithContext(execCtx, streamOpts)
	result := stdout.String()
	errOut := stderr.String()

	if err != nil {
		if errOut != "" {
			return "", fmt.Errorf("exec tar extract failed: %s (stderr: %s)", err.Error(), errOut)
		}
		return "", fmt.Errorf("exec tar extract failed: %w", err)
	}

	if errOut != "" {
		return result, fmt.Errorf("tar stderr: %s", errOut)
	}

	// Verify the file was written
	verifyCmd := []string{"ls", "-la", destPath}
	verifyResult, verifyErr := c.ExecInPodResult(ctx, namespace, podName, containerName, verifyCmd)
	if verifyErr == nil {
		result = result + "\n" + verifyResult.Stdout
	}

	return fmt.Sprintf("File uploaded: %s -> %s/%s:%s (%d bytes)\n%s", srcPath, namespace, podName, destPath, len(data), result), nil
}

// UploadBytes uploads raw bytes to a pod (same as UploadFile but from memory)
func (c *Client) UploadBytes(ctx context.Context, namespace, podName, containerName string, data []byte, destPath string) (string, error) {
	if containerName == "" {
		containerName = c.getDefaultContainer(ctx, namespace, podName)
		if containerName == "" {
			return "", fmt.Errorf("no container found in pod %s/%s", namespace, podName)
		}
	}

	fileName := filepath.Base(destPath)
	destDir := filepath.Dir(destPath)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{
		Name: fileName,
		Mode: 0755,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return "", fmt.Errorf("tar write header: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return "", fmt.Errorf("tar write data: %w", err)
	}
	tw.Close()

	execCmd := []string{"tar", "-xmf", "-", "-C", destDir}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   execCmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create SPDY executor: %w", err)
	}

	streamOpts := remotecommand.StreamOptions{
		Stdin:  &tarBuf,
		Stdout: stdout,
		Stderr: stderr,
	}

	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err = exec.StreamWithContext(execCtx, streamOpts)
	if err != nil {
		return "", fmt.Errorf("upload bytes failed: %w (stderr: %s)", err, stderr.String())
	}

	// Make executable if it looks like a binary
	if strings.HasSuffix(destPath, ".bin") || strings.HasSuffix(destPath, ".sh") {
		chmodCmd := []string{"chmod", "+x", destPath}
		if _, chmodErr := c.ExecInPodResult(ctx, namespace, podName, containerName, chmodCmd); chmodErr != nil {
			// chmod failure is non-fatal; file is uploaded but may lack exec permission
			return fmt.Sprintf("Uploaded %d bytes to %s/%s:%s (chmod failed: %v)", len(data), namespace, podName, destPath, chmodErr), nil
		}
	}

	return fmt.Sprintf("Uploaded %d bytes to %s/%s:%s", len(data), namespace, podName, destPath), nil
}

// DownloadFile downloads a file from a pod (equivalent to kubectl cp pod:/path /local/path)
func (c *Client) DownloadFile(ctx context.Context, namespace, podName, containerName, srcPath, destPath string) (string, error) {
	if containerName == "" {
		containerName = c.getDefaultContainer(ctx, namespace, podName)
		if containerName == "" {
			return "", fmt.Errorf("no container found in pod %s/%s", namespace, podName)
		}
	}

	execCmd := []string{"tar", "-cf", "-", "-C", filepath.Dir(srcPath), filepath.Base(srcPath)}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   execCmd,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create SPDY executor: %w", err)
	}

	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err = exec.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})

	if err != nil {
		return "", fmt.Errorf("download tar failed: %w (stderr: %s)", err, stderr.String())
	}

	// Extract the file from tar
	tr := tar.NewReader(stdout)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar header: %w", err)
		}
		if hdr.Name == filepath.Base(srcPath) {
			f, err := os.Create(destPath)
			if err != nil {
				return "", fmt.Errorf("create dest file: %w", err)
			}
			defer f.Close()
			if _, err := io.Copy(f, tr); err != nil {
				return "", fmt.Errorf("write dest file: %w", err)
			}
			return fmt.Sprintf("Downloaded %s/%s:%s -> %s (%d bytes)", namespace, podName, srcPath, destPath, hdr.Size), nil
		}
	}

	return "", fmt.Errorf("file %s not found in tar from pod", srcPath)
}

// getDefaultContainer returns the first container name in a pod
func (c *Client) getDefaultContainer(ctx context.Context, namespace, podName string) string {
	pod, err := c.GetPod(ctx, namespace, podName)
	if err != nil || pod == nil {
		return ""
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name
	}
	return ""
}
