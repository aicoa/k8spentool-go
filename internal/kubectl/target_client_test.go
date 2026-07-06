package kubectl

import "testing"

func TestAPIServerURL(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		{name: "plain host", host: "10.0.0.1", want: "https://10.0.0.1:6443"},
		{name: "host with port", host: "10.0.0.1:7443", want: "https://10.0.0.1:7443"},
		{name: "explicit https", host: "https://cluster.local:9443", want: "https://cluster.local:9443"},
		{name: "ipv6 host", host: "2001:db8::10", want: "https://[2001:db8::10]:6443"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := APIServerURL(tc.host); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestTargetHostnameAndTargetServiceURL(t *testing.T) {
	cases := []struct {
		name        string
		host        string
		wantHost    string
		wantService string
	}{
		{name: "plain host", host: "10.0.0.1", wantHost: "10.0.0.1", wantService: "https://10.0.0.1:10250/pods"},
		{name: "host with port", host: "demo.local:7443", wantHost: "demo.local", wantService: "https://demo.local:10250/pods"},
		{name: "explicit https", host: "https://cluster.local:9443", wantHost: "cluster.local", wantService: "https://cluster.local:10250/pods"},
		{name: "ipv6 host", host: "2001:db8::10", wantHost: "2001:db8::10", wantService: "https://[2001:db8::10]:10250/pods"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TargetHostname(tc.host); got != tc.wantHost {
				t.Fatalf("TargetHostname(%q) = %q, want %q", tc.host, got, tc.wantHost)
			}
			if got := TargetServiceURL(tc.host, "https", 10250, "/pods"); got != tc.wantService {
				t.Fatalf("TargetServiceURL(%q) = %q, want %q", tc.host, got, tc.wantService)
			}
		})
	}
}

func TestNewTargetClientAllowsAnonymous(t *testing.T) {
	client, err := NewTargetClient("demo.local", "", "", "", true)
	if err != nil {
		t.Fatalf("expected anonymous client to be created, got error: %v", err)
	}
	if client == nil || client.config == nil {
		t.Fatalf("expected client config to be initialized")
	}
	if client.config.Host != "https://demo.local:6443" {
		t.Fatalf("expected normalized host, got %q", client.config.Host)
	}
}
