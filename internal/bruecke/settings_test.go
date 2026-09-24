package bruecke

import "testing"

func TestNormalizeVPNSettings(t *testing.T) {
	settings, err := normalizeVPNSettings(VPNSettings{
		WGCIDR:         "10.44.0.0/24",
		WGServerIP:     "10.44.0.1",
		WGIPv6CIDR:     "fd44:44:44::/64",
		WGIPv6ServerIP: "fd44:44:44::1",
		DNSServers:     []string{"10.44.0.1", " 1.1.1.1 ", "10.44.0.1"},
		SearchDomain:   "CORP.EXAMPLE.COM.",
	})
	if err != nil {
		t.Fatalf("normalize settings: %v", err)
	}
	if len(settings.DNSServers) != 2 {
		t.Fatalf("dns servers=%v", settings.DNSServers)
	}
	if settings.SearchDomain != "corp.example.com" {
		t.Fatalf("search domain=%q", settings.SearchDomain)
	}
}

func TestNormalizeVPNSettingsRejectsTooManyDNSServers(t *testing.T) {
	_, err := normalizeVPNSettings(VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1", DNSServers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "10.44.0.1"}})
	if err == nil {
		t.Fatalf("expected too many DNS servers error")
	}
}

func TestNormalizeVPNSettingsRejectsInvalidDNSServer(t *testing.T) {
	_, err := normalizeVPNSettings(VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1", DNSServers: []string{"dns.example.com"}})
	if err == nil {
		t.Fatalf("expected invalid DNS server error")
	}
}

func TestDNSConfigLineIncludesSearchDomain(t *testing.T) {
	store, err := OpenSettingsStore(t.TempDir()+"/settings.json", VPNSettings{
		WGCIDR:         "10.44.0.0/24",
		WGServerIP:     "10.44.0.1",
		WGIPv6CIDR:     "fd44:44:44::/64",
		WGIPv6ServerIP: "fd44:44:44::1",
		DNSServers:     []string{"10.44.0.1", "1.1.1.1"},
		SearchDomain:   "corp.example.com",
	})
	if err != nil {
		t.Fatalf("open settings: %v", err)
	}
	server := NewServer(Config{}, ServerDependencies{Settings: store})
	if got := server.dnsConfigLine(); got != "10.44.0.1, 1.1.1.1, corp.example.com" {
		t.Fatalf("dns line=%q", got)
	}
}
