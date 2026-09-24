package bruecke

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteSubnetStoreAllowedCIDRs(t *testing.T) {
	store, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	free, err := store.Add("Free", "ovpn", "free.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, nil, []string{AllGroupID}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add free subnet: %v", err)
	}
	selected, err := store.Add("Selected", "ovpn", "selected.ovpn", "client\nremote vpn 1194", []string{"10.20.0.0/24"}, nil, nil, time.Unix(2, 0))
	if err != nil {
		t.Fatalf("add selected subnet: %v", err)
	}

	withoutSelection := store.AllowedCIDRs(nil)
	if strings.Join(withoutSelection, ",") != "10.10.0.0/24" {
		t.Fatalf("without selection=%v free=%s", withoutSelection, free.ID)
	}
	withSelection := store.AllowedCIDRs([]string{selected.ID})
	if strings.Join(withSelection, ",") != "10.10.0.0/24,10.20.0.0/24" {
		t.Fatalf("with selection=%v", withSelection)
	}
}

func TestRemoteSubnetStoreRestrictedIDsRejectsFreeForAll(t *testing.T) {
	store, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	free, err := store.Add("Free", "ovpn", "free.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, nil, []string{AllGroupID}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add free subnet: %v", err)
	}
	selected, err := store.Add("Selected", "ovpn", "selected.ovpn", "client\nremote vpn 1194", []string{"10.20.0.0/24"}, nil, nil, time.Unix(2, 0))
	if err != nil {
		t.Fatalf("add selected subnet: %v", err)
	}
	ids, err := store.RestrictedIDs([]string{selected.ID})
	if err != nil {
		t.Fatalf("restricted ids: %v", err)
	}
	if strings.Join(ids, ",") != selected.ID {
		t.Fatalf("ids=%v", ids)
	}
	if _, err := store.RestrictedIDs([]string{free.ID}); err == nil {
		t.Fatalf("all-group subnet accepted as restricted id")
	}
}

func TestRemoteSubnetStoreUpdateEnabledOnly(t *testing.T) {
	store, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	subnet, err := store.Add("Site", "ovpn", "site.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, nil, []string{AllGroupID}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add subnet: %v", err)
	}
	enabled := false
	updated, err := store.Update(subnet.ID, RemoteSubnetUpdate{Enabled: &enabled})
	if err != nil {
		t.Fatalf("disable subnet: %v", err)
	}
	if updated.Enabled {
		t.Fatalf("subnet still enabled")
	}
	if updated.Name != "Site" || strings.Join(updated.Subnets, ",") != "10.10.0.0/24" || strings.Join(updated.GroupIDs, ",") != AllGroupID {
		t.Fatalf("partial update changed other fields: %+v", updated)
	}
}

func TestRemoteSubnetStoreRemoveClient(t *testing.T) {
	store, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	subnet, err := store.Add("Site", "ovpn", "site.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, []string{"pc1", "pc2"}, nil, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add subnet: %v", err)
	}
	if err := store.RemoveClient("pc1"); err != nil {
		t.Fatalf("remove client: %v", err)
	}
	views := store.Subnets()
	if len(views) != 1 || views[0].ID != subnet.ID {
		t.Fatalf("views=%+v", views)
	}
	if containsID(views[0].ClientIDs, "pc1") || !containsID(views[0].ClientIDs, "pc2") {
		t.Fatalf("client IDs=%v", views[0].ClientIDs)
	}
	reopened, err := OpenRemoteSubnetStore(filepath.Join(filepath.Dir(store.path), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("reopen remote subnet store: %v", err)
	}
	if containsID(reopened.Subnets()[0].ClientIDs, "pc1") {
		t.Fatalf("removed client persisted")
	}
}

func TestConvertAPCToOVPN(t *testing.T) {
	ovpn, creds, err := convertAPCToOVPN(`{
  "protocol":"udp",
  "server_address":["vpn.example.com"],
  "server_port":1194,
  "authentication_algorithm":"SHA256",
  "encryption_algorithm":"AES-256-CBC",
  "server_dn":"CN=vpn.example.com,O=example",
  "ca_cert":"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
  "certificate":"-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
  "key":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
  "username":"user",
  "password":"pass"
}`, "site.apc")
	if err != nil {
		t.Fatalf("convert APC: %v", err)
	}
	for _, want := range []string{"proto udp", "remote vpn.example.com 1194", "verify-x509-name vpn.example.com name", "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC", "data-ciphers-fallback AES-256-CBC", "auth-user-pass site-creds.txt", "auth-nocache", "pull-filter ignore \"redirect-gateway\""} {
		if !strings.Contains(ovpn, want) {
			t.Fatalf("OVPN missing %q:\n%s", want, ovpn)
		}
	}
	if strings.Contains(ovpn, "remote-cert-tls server") {
		t.Fatalf("OVPN should not require server KU bit:\n%s", ovpn)
	}
	if creds != "user\npass\n" {
		t.Fatalf("creds=%q", creds)
	}
}

func TestRemoteSubnetStoreRebuildsStoredAPC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote-subnets.json")
	apc := `{
  "protocol":"tcp",
  "server_address":["vpn.example.com"],
  "server_port":"8443",
  "authentication_algorithm":"SHA1",
  "encryption_algorithm":"AES-128-CBC",
  "server_dn":"CN=vpn.example.com,O=example",
  "ca_cert":"ca",
  "certificate":"cert",
  "key":"key",
  "username":"user",
  "password":"pass"
}`
	state := RemoteSubnetState{Version: 1, Subnets: map[string]RemoteSubnetSpec{
		"apc1": {
			ID:             "apc1",
			Name:           "APC",
			ConfigType:     "apc",
			SourceFilename: "site.apc",
			Subnets:        []string{"10.10.0.0/24"},
			FreeForAll:     true,
			Enabled:        true,
			APCConfig:      apc,
			OVPNConfig:     "client\nremote-cert-tls server\n",
			CreatedAt:      time.Unix(1, 0),
			UpdatedAt:      time.Unix(1, 0),
		},
	}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	store, err := OpenRemoteSubnetStore(path)
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	specs := store.Specs()
	if len(specs) != 1 {
		t.Fatalf("specs=%d", len(specs))
	}
	if !strings.Contains(specs[0].OVPNConfig, "verify-x509-name vpn.example.com name") {
		t.Fatalf("stored APC was not rebuilt:\n%s", specs[0].OVPNConfig)
	}
	if strings.Contains(specs[0].OVPNConfig, "remote-cert-tls server") {
		t.Fatalf("rebuilt APC should not require server KU bit:\n%s", specs[0].OVPNConfig)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	if strings.Contains(string(persisted), "remote-cert-tls server") {
		t.Fatalf("persisted APC was not rebuilt")
	}
}

func TestClientConfigHidesRemoteSubnets(t *testing.T) {
	store, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	_, err = store.Add("Free", "ovpn", "free.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, nil, []string{AllGroupID}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add free subnet: %v", err)
	}
	server := NewServer(Config{WGClientAllowedIPs: "0.0.0.0/0", WGServerPublicKey: "server", WGEndpoint: "server:51820"}, ServerDependencies{RemoteSubnets: store})
	config := server.renderClientConfig("private", Client{IP: "10.44.0.2", IPv6: "fd44::2"})
	if strings.Contains(config, "10.10.0.0/24") {
		t.Fatalf("remote subnet leaked into client config:\n%s", config)
	}
}

func TestRemoteSubnetAllowedForClientUsesClientsGroupsAndLegacyIDs(t *testing.T) {
	client := Client{ID: "pc1|root-a", GroupIDs: []string{AllGroupID, "domain:root-a", "custom:ops"}, RemoteSubnetIDs: []string{"legacy"}}
	for name, spec := range map[string]RemoteSubnetSpec{
		"all":    {ID: "all-site", GroupIDs: []string{AllGroupID}},
		"client": {ID: "client-site", ClientIDs: []string{client.ID}},
		"group":  {ID: "group-site", GroupIDs: []string{"custom:ops"}},
		"legacy": {ID: "legacy"},
	} {
		if !remoteSubnetAllowedForClient(spec, client) {
			t.Fatalf("%s grant denied", name)
		}
	}
	if remoteSubnetAllowedForClient(RemoteSubnetSpec{ID: "other", GroupIDs: []string{"custom:other"}}, client) {
		t.Fatalf("unrelated grant accepted")
	}
}
