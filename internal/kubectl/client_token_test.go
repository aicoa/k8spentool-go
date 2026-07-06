package kubectl

import (
	"context"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestRequestServiceAccountTokenUsesTokenRequestSubresource(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("create", "serviceaccounts", func(action clienttesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(clienttesting.CreateAction)
		if !ok {
			t.Fatalf("expected create action, got %T", action)
		}
		if createAction.GetSubresource() != "token" {
			t.Fatalf("expected token subresource, got %q", createAction.GetSubresource())
		}
		obj, ok := createAction.GetObject().(*authenticationv1.TokenRequest)
		if !ok {
			t.Fatalf("expected TokenRequest object, got %T", createAction.GetObject())
		}
		if obj.Spec.ExpirationSeconds == nil || *obj.Spec.ExpirationSeconds != 3600 {
			t.Fatalf("expected expirationSeconds=3600, got %#v", obj.Spec.ExpirationSeconds)
		}
		return true, &authenticationv1.TokenRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "demo"},
			Status:     authenticationv1.TokenRequestStatus{Token: "issued-token"},
		}, nil
	})

	token, err := requestServiceAccountToken(context.Background(), clientset.CoreV1().ServiceAccounts("kube-system"), "demo", 3600)
	if err != nil {
		t.Fatalf("expected token request to succeed, got %v", err)
	}
	if token != "issued-token" {
		t.Fatalf("expected issued-token, got %q", token)
	}
}
