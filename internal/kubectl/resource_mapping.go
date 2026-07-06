package kubectl

import "strings"

func resourceForKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "pod", "pods":
		return "pods"
	case "service", "services", "svc":
		return "services"
	case "secret", "secrets":
		return "secrets"
	case "configmap", "configmaps", "cm":
		return "configmaps"
	case "serviceaccount", "serviceaccounts", "sa":
		return "serviceaccounts"
	case "deployment", "deployments", "deploy":
		return "deployments"
	case "daemonset", "daemonsets", "ds":
		return "daemonsets"
	case "statefulset", "statefulsets", "sts":
		return "statefulsets"
	case "cronjob", "cronjobs", "cj":
		return "cronjobs"
	case "job", "jobs":
		return "jobs"
	case "ingress", "ingresses", "ing":
		return "ingresses"
	case "networkpolicy", "networkpolicies", "netpol":
		return "networkpolicies"
	case "persistentvolumeclaim", "persistentvolumeclaims", "pvc":
		return "persistentvolumeclaims"
	case "persistentvolume", "persistentvolumes", "pv":
		return "persistentvolumes"
	case "role", "roles":
		return "roles"
	case "rolebinding", "rolebindings", "rb":
		return "rolebindings"
	case "clusterrole", "clusterroles", "cr":
		return "clusterroles"
	case "clusterrolebinding", "clusterrolebindings", "crb":
		return "clusterrolebindings"
	case "namespace", "namespaces", "ns":
		return "namespaces"
	default:
		return strings.ToLower(strings.TrimSpace(kind)) + "s"
	}
}
