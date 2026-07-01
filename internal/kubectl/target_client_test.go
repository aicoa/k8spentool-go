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
