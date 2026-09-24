package bruecke

import "testing"

func TestWireGuardInterfaceSettingsUseVPNSettings(t *testing.T) {
	settings := VPNSettings{
		WGCIDR:         "10.241.0.0/24",
		WGServerIP:     "10.241.0.1",
		WGIPv6CIDR:     "fd44:44:44::/64",
		WGIPv6ServerIP: "fd44:44:44::1",
	}

	addressCIDRs, networks, ipv6Networks, err := wireGuardInterfaceSettings(settings)
	if err != nil {
		t.Fatalf("interface settings: %v", err)
	}
	if addressCIDRs != "10.241.0.1/24,fd44:44:44::1/64" {
		t.Fatalf("address CIDRs=%q", addressCIDRs)
	}
	if len(networks) != 1 || networks[0] != "10.241.0.0/24" {
		t.Fatalf("networks=%v", networks)
	}
	if len(ipv6Networks) != 1 || ipv6Networks[0] != "fd44:44:44::/64" {
		t.Fatalf("IPv6 networks=%v", ipv6Networks)
	}
}

func TestSameWireGuardInterfaceSettingsIgnoresDNS(t *testing.T) {
	a := VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1", DNSServers: []string{"9.9.9.9"}}
	b := VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1", DNSServers: []string{"1.1.1.1"}}

	if !sameWireGuardInterfaceSettings(a, b) {
		t.Fatalf("DNS-only settings change should not require interface reset")
	}
}
