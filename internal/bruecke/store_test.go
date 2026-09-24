package bruecke

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRotateKeepsIPAndReplacesPublicKey(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	var calls []struct {
		oldPublicKey string
		allowedIP    string
		enabled      bool
	}
	apply := func(oldPublicKey, allowedIP string, enabled bool) error {
		calls = append(calls, struct {
			oldPublicKey string
			allowedIP    string
			enabled      bool
		}{oldPublicKey: oldPublicKey, allowedIP: allowedIP, enabled: enabled})
		return nil
	}

	first, err := store.Rotate(context.Background(), Enrollment{
		Hostname:  "pc1.example.com",
		DomainID:  "domain-a",
		Settings:  testVPNSettings(),
		PublicKey: "pub1",
		IssuedAt:  time.Unix(1, 0),
	}, apply)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if first.IP != "10.44.0.2" {
		t.Fatalf("first IP=%s", first.IP)
	}
	if first.IPv6 != "fd44:44:44::2" {
		t.Fatalf("first IPv6=%s", first.IPv6)
	}

	second, err := store.Rotate(context.Background(), Enrollment{
		Hostname:  "pc1.example.com",
		DomainID:  "domain-a",
		Settings:  testVPNSettings(),
		PublicKey: "pub2",
		IssuedAt:  time.Unix(2, 0),
	}, apply)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if second.IP != first.IP {
		t.Fatalf("rotated IP=%s, want %s", second.IP, first.IP)
	}
	if second.PublicKey != "pub2" {
		t.Fatalf("public key=%s", second.PublicKey)
	}
	if len(calls) != 2 {
		t.Fatalf("calls=%d", len(calls))
	}
	if calls[0].oldPublicKey != "" || calls[0].allowedIP != "10.44.0.2/32,fd44:44:44::2/128" || !calls[0].enabled {
		t.Fatalf("first call=%+v", calls[0])
	}
	if calls[1].oldPublicKey != "pub1" || calls[1].allowedIP != "10.44.0.2/32,fd44:44:44::2/128" || !calls[1].enabled {
		t.Fatalf("second call=%+v", calls[1])
	}

	reopened, err := OpenStore(store.path, network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	clients := reopened.Clients()
	if len(clients) != 1 {
		t.Fatalf("clients=%d", len(clients))
	}
	if clients[0].PublicKey != "pub2" {
		t.Fatalf("stored public key=%s", clients[0].PublicKey)
	}
}

func TestStoreDisableClientAndRotateKeepsDeadEndState(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	first, err := store.Rotate(context.Background(), testEnrollment("pc1", "pub1"), nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first.Disabled {
		t.Fatalf("new client should be enabled")
	}

	var applied Client
	disabled, err := store.SetClientEnabled(context.Background(), "pc1", false, func(client Client) error {
		applied = client
		return nil
	})
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !disabled.Disabled || !applied.Disabled {
		t.Fatalf("client should be disabled: stored=%v applied=%v", disabled.Disabled, applied.Disabled)
	}

	var rotateEnabled bool
	rotated, err := store.Rotate(context.Background(), testEnrollment("pc1", "pub2"), func(oldPublicKey, allowedIP string, enabled bool) error {
		rotateEnabled = enabled
		return nil
	})
	if err != nil {
		t.Fatalf("rotate disabled: %v", err)
	}
	if !rotated.Disabled {
		t.Fatalf("rotated client should stay disabled")
	}
	if rotateEnabled {
		t.Fatalf("disabled client rotation should apply dead-end peer")
	}
}

func TestStoreDeleteClientRemovesCustomGroupMembership(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	client, err := store.Rotate(context.Background(), testEnrollment("pc1", "pub1"), nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	group, err := store.AddGroup("Ops", time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add group: %v", err)
	}
	clientIDs := []string{client.ID}
	if _, err := store.UpdateGroup(group.ID, nil, &clientIDs, nil); err != nil {
		t.Fatalf("assign group: %v", err)
	}

	var applied Client
	deleted, err := store.DeleteClient(context.Background(), client.ID, func(client Client) error {
		applied = client
		return nil
	})
	if err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if deleted.ID != client.ID || applied.ID != client.ID {
		t.Fatalf("deleted=%+v applied=%+v", deleted, applied)
	}
	if _, err := store.Client(client.ID); err == nil {
		t.Fatalf("client still exists")
	}
	groups := store.Groups(nil)
	for _, view := range groups {
		if view.ID == group.ID && containsID(view.ClientIDs, client.ID) {
			t.Fatalf("deleted client still in group: %+v", view)
		}
	}
}

func TestStoreRotateAllocatesUniqueIPs(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	first, err := store.Rotate(context.Background(), testEnrollment("pc1", "pub1"), nil)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	second, err := store.Rotate(context.Background(), testEnrollment("pc2", "pub2"), nil)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if first.IP == second.IP {
		t.Fatalf("duplicate IP %s", first.IP)
	}
	if first.IPv6 == second.IPv6 {
		t.Fatalf("duplicate IPv6 %s", first.IPv6)
	}
}

func TestStoreSameHostnameDifferentDomainsAreDistinctClients(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	first, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-a", DomainName: "Domain A", Settings: testVPNSettings(), PublicKey: "pub-a"}, nil)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	second, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-b", DomainName: "Domain B", Settings: testVPNSettings(), PublicKey: "pub-b"}, nil)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if first.ID == second.ID || first.IP == second.IP || first.IPv6 == second.IPv6 {
		t.Fatalf("clients not distinct: first=%+v second=%+v", first, second)
	}
	if !containsID(first.GroupIDs, domainGroupID("domain-a")) || !containsID(second.GroupIDs, domainGroupID("domain-b")) {
		t.Fatalf("root groups missing: first=%v second=%v", first.GroupIDs, second.GroupIDs)
	}

	clients := store.Clients()
	if len(clients) != 2 {
		t.Fatalf("clients=%d", len(clients))
	}
}

func TestStoreGroupsSupportNestedMembershipAndRejectRecursion(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	client, err := store.Rotate(context.Background(), testEnrollment("pc1", "pub1"), nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	parent, err := store.AddGroup("Parent", time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add parent: %v", err)
	}
	child, err := store.AddGroup("Child", time.Unix(2, 0))
	if err != nil {
		t.Fatalf("add child: %v", err)
	}
	clientIDs := []string{client.ID}
	if _, err := store.UpdateGroup(child.ID, nil, &clientIDs, nil); err != nil {
		t.Fatalf("assign child client: %v", err)
	}
	childIDs := []string{child.ID}
	if _, err := store.UpdateGroup(parent.ID, nil, nil, &childIDs); err != nil {
		t.Fatalf("assign parent child: %v", err)
	}
	updated, err := store.Client(client.ID)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if !containsID(updated.GroupIDs, child.ID) || !containsID(updated.GroupIDs, parent.ID) {
		t.Fatalf("nested groups missing: %v", updated.GroupIDs)
	}
	parentIDs := []string{parent.ID}
	if _, err := store.UpdateGroup(child.ID, nil, nil, &parentIDs); err == nil {
		t.Fatalf("recursive group accepted")
	}
}

func TestStoreRotateUsesDomainSettings(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	client, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-a", DomainName: "Domain A", PublicKey: "pub1", Settings: VPNSettings{WGCIDR: "10.60.0.0/21", WGServerIP: "10.60.0.1", WGIPv6CIDR: "fd44:44:60::/64", WGIPv6ServerIP: "fd44:44:60::1"}}, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if client.IP != "10.60.0.2" || client.IPv6 != "fd44:44:60::2" {
		t.Fatalf("domain lease=%s/%s", client.IP, client.IPv6)
	}
}

func TestStoreGroupViewsExposeBuiltInMembership(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	client, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "root-a", PublicKey: "pub1", Settings: testVPNSettings()}, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	views := store.Groups([]Domain{{ID: "root-a", Name: "Root A"}})
	var all, root GroupView
	for _, view := range views {
		if view.ID == AllGroupID {
			all = view
		}
		if view.ID == domainGroupID("root-a") {
			root = view
		}
	}
	if !containsID(all.ClientIDs, client.ID) || !containsID(all.GroupIDs, domainGroupID("root-a")) {
		t.Fatalf("all group membership missing: %+v", all)
	}
	if !containsID(root.ClientIDs, client.ID) {
		t.Fatalf("root group membership missing: %+v", root)
	}
}

func TestStoreRotateFailsWhenPoolIsFull(t *testing.T) {
	network := netip.MustParsePrefix("10.44.0.0/30")
	serverIP := netip.MustParseAddr("10.44.0.1")
	ipv6Net := netip.MustParsePrefix("fd44:44:44::/126")
	ipv6IP := netip.MustParseAddr("fd44:44:44::1")
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	settings := VPNSettings{WGCIDR: network.String(), WGServerIP: serverIP.String(), WGIPv6CIDR: ipv6Net.String(), WGIPv6ServerIP: ipv6IP.String()}
	if _, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-a", PublicKey: "pub1", Settings: settings}, nil); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if _, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc2", DomainID: "domain-a", PublicKey: "pub2", Settings: settings}, nil); err == nil {
		t.Fatalf("expected pool full error")
	}
}

func testPools() (netip.Prefix, netip.Addr, netip.Prefix, netip.Addr) {
	return netip.MustParsePrefix("10.44.0.0/29"), netip.MustParseAddr("10.44.0.1"), netip.MustParsePrefix("fd44:44:44::/120"), netip.MustParseAddr("fd44:44:44::1")
}

func testVPNSettings() VPNSettings {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	return VPNSettings{WGCIDR: network.String(), WGServerIP: serverIP.String(), WGIPv6CIDR: ipv6Net.String(), WGIPv6ServerIP: ipv6IP.String()}
}

func testEnrollment(hostname, publicKey string) Enrollment {
	return Enrollment{Hostname: hostname, DomainID: "domain-a", DomainName: "Domain A", PublicKey: publicKey, Settings: testVPNSettings()}
}
