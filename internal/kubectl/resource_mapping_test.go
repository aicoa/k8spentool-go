package kubectl

import "testing"

func TestResourceForKindHandlesIrregularPluralization(t *testing.T) {
	cases := map[string]string{
		"Ingress":               "ingresses",
		"NetworkPolicy":         "networkpolicies",
		"StatefulSet":           "statefulsets",
		"PersistentVolumeClaim": "persistentvolumeclaims",
		"PersistentVolume":      "persistentvolumes",
	}

	for kind, want := range cases {
		if got := resourceForKind(kind); got != want {
			t.Fatalf("resourceForKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestResourceForKindSupportsShortAliases(t *testing.T) {
	cases := map[string]string{
		"svc":    "services",
		"sa":     "serviceaccounts",
		"ds":     "daemonsets",
		"sts":    "statefulsets",
		"ing":    "ingresses",
		"netpol": "networkpolicies",
		"pvc":    "persistentvolumeclaims",
		"pv":     "persistentvolumes",
	}

	for kind, want := range cases {
		if got := resourceForKind(kind); got != want {
			t.Fatalf("resourceForKind(%q) = %q, want %q", kind, got, want)
		}
	}
}
