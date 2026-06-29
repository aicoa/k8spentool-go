package handler

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestClassifyDashboardTokenResult(t *testing.T) {
	gvr := schema.GroupResource{Group: "", Resource: "namespaces"}

	tests := []struct {
		name      string
		err       error
		wantValid bool
		wantState string
	}{
		{name: "cluster access", err: nil, wantValid: true, wantState: "cluster_api_access"},
		{name: "restricted rbac", err: apierrors.NewForbidden(gvr, "", nil), wantValid: true, wantState: "restricted_rbac"},
		{name: "unauthorized", err: apierrors.NewUnauthorized("bad token"), wantValid: false, wantState: "unauthorized"},
		{name: "network issue", err: apierrors.NewTimeoutError("timeout", 1), wantValid: false, wantState: "unverified"},
		{name: "not found", err: apierrors.NewNotFound(gvr, "demo"), wantValid: false, wantState: "unverified"},
		{name: "conflict", err: apierrors.NewConflict(gvr, "demo", nil), wantValid: false, wantState: "unverified"},
		{name: "server timeout", err: apierrors.NewServerTimeout(gvr, "list", 1), wantValid: false, wantState: "unverified"},
		{name: "unexpected", err: apierrors.NewInternalError(errors.New("boom")), wantValid: false, wantState: "unverified"},
		{name: "status error", err: &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonForbidden}}, wantValid: true, wantState: "restricted_rbac"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValid, gotState := classifyDashboardTokenResult(tt.err)
			if gotValid != tt.wantValid || gotState != tt.wantState {
				t.Fatalf("expected (%v, %q), got (%v, %q)", tt.wantValid, tt.wantState, gotValid, gotState)
			}
		})
	}
}

func TestDetectDashboardSkipLogin(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want bool
	}{
		{name: "real marker text", path: "/", body: "<button>Skip Login</button>", want: true},
		{name: "angular route", path: "/", body: `<a href="/#/login?skip=true">continue</a>`, want: true},
		{name: "generic skip text", path: "/", body: "skip to content", want: false},
		{name: "api body should not count", path: "/api/v1/", body: `{"message":"skip cache"}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectDashboardSkipLogin(tt.path, tt.body); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
