package bruecke

import "testing"

func TestLoadConfigDerivesWireGuardListenPort(t *testing.T) {
	setConfigTestEnv(t)
	t.Setenv("BRUECKE_WG_ENDPOINT", "vpn.example.com:12345")
	t.Setenv("BRUECKE_WG_LISTEN_PORT", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.WGListenPort != 12345 {
		t.Fatalf("listen port=%d", cfg.WGListenPort)
	}
	if cfg.WGPrivateKeyFile != "/data/wg-server.key" {
		t.Fatalf("private key file=%q", cfg.WGPrivateKeyFile)
	}
	if cfg.WGOutboundInterface != "auto" {
		t.Fatalf("outbound interface=%q", cfg.WGOutboundInterface)
	}
}

func TestLoadConfigExplicitWireGuardListenPortOverridesEndpoint(t *testing.T) {
	setConfigTestEnv(t)
	t.Setenv("BRUECKE_WG_ENDPOINT", "vpn.example.com:51820")
	t.Setenv("BRUECKE_WG_LISTEN_PORT", "12345")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.WGListenPort != 12345 {
		t.Fatalf("listen port=%d", cfg.WGListenPort)
	}
}

func TestLoadConfigNormalizesPublicURL(t *testing.T) {
	setConfigTestEnv(t)
	t.Setenv("BRUECKE_WG_ENDPOINT", "vpn.example.com:51820")
	t.Setenv("BRUECKE_PUBLIC_URL", " https://vpn.example.com/ ")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.PublicURL != "https://vpn.example.com" {
		t.Fatalf("public URL=%q", cfg.PublicURL)
	}
}

func TestLoadConfigRejectsPublicURLPath(t *testing.T) {
	setConfigTestEnv(t)
	t.Setenv("BRUECKE_WG_ENDPOINT", "vpn.example.com:51820")
	t.Setenv("BRUECKE_PUBLIC_URL", "https://vpn.example.com/bruecke")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected public URL validation error")
	}
}

func setConfigTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BRUECKE_DATA_DIR", "/data")
	t.Setenv("BRUECKE_TLS_TERMINATE", "false")
	t.Setenv("BRUECKE_WG_CIDR", "10.44.0.0/24")
	t.Setenv("BRUECKE_WG_SERVER_IP", "")
	t.Setenv("BRUECKE_WG_IPV6_CIDR", "fd44:44:44::/64")
	t.Setenv("BRUECKE_WG_IPV6_SERVER_IP", "")
	t.Setenv("BRUECKE_WG_SERVER_PUBLIC_KEY", "server-public-key")
	t.Setenv("BRUECKE_WG_PERSISTENT_KEEPALIVE", "25")
	t.Setenv("BRUECKE_APPLY_WG", "true")
	t.Setenv("BRUECKE_ADMIN_COOKIE_SECURE", "true")
	t.Setenv("BRUECKE_ADMIN_SESSION_SECONDS", "43200")
	t.Setenv("BRUECKE_WG_CONNECTED_SECONDS", "180")
	t.Setenv("BRUECKE_WG_PRIVATE_KEY_FILE", "")
	t.Setenv("BRUECKE_WG_OUTBOUND_INTERFACE", "")
	t.Setenv("BRUECKE_PUBLIC_URL", "")
}
