package handler

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

type kubeletContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type kubeletPodSpec struct {
	NodeName   string             `json:"nodeName"`
	Containers []kubeletContainer `json:"containers"`
}

type kubeletPodMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type kubeletPodStatus struct {
	Phase string `json:"phase"`
	PodIP string `json:"podIP"`
}

type kubeletPod struct {
	Metadata kubeletPodMeta   `json:"metadata"`
	Spec     kubeletPodSpec   `json:"spec"`
	Status   kubeletPodStatus `json:"status"`
}

type kubeletPodList struct {
	Items []kubeletPod `json:"items"`
}

func parseKubeletPodList(body []byte) ([]kubeletPod, error) {
	var podList kubeletPodList
	if err := json.Unmarshal(body, &podList); err != nil {
		return nil, fmt.Errorf("failed to parse pod list: %w", err)
	}
	return podList.Items, nil
}

func flattenKubeletPods(items []kubeletPod) []gin.H {
	result := make([]gin.H, 0, len(items))
	for _, pod := range items {
		ns := pod.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		status := strings.TrimSpace(pod.Status.Phase)
		if status == "" {
			status = "Unknown"
		}
		containers := make([]string, 0, len(pod.Spec.Containers))
		images := make([]string, 0, len(pod.Spec.Containers))
		for _, c := range pod.Spec.Containers {
			if c.Name != "" {
				containers = append(containers, c.Name)
			}
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
		result = append(result, gin.H{
			"namespace":  ns,
			"name":       pod.Metadata.Name,
			"status":     status,
			"node":       pod.Spec.NodeName,
			"ip":         pod.Status.PodIP,
			"containers": strings.Join(containers, ", "),
			"images":     strings.Join(images, ", "),
		})
	}
	return result
}

func shellQuoteSingle(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func kubeletExecHasMarker(statusCode int, body []byte, execErr error, marker string) bool {
	if execErr != nil || statusCode != 200 {
		return false
	}
	output := strings.TrimSpace(string(body))
	if output == "" {
		return false
	}
	return strings.Contains(output, marker)
}
