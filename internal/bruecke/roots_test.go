package bruecke

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootStoreCreatesManualOnlyDomainsWithGeneratedPools(t *testing.T) {
	store, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1", DNSServers: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	localNetworks := []DomainLocalNetwork{
		{Type: "wifi", Name: " Headquarters Wi-Fi ", SSID: " Corp Wi-Fi ", Gateway: "192.168.10.1", Subnet: "192.168.10.12/24", SearchDomain: "CORP.EXAMPLE."},
		{Type: "ethernet", Name: "Headquarters wired", Gateway: "10.10.0.1", Subnet: "10.10.0.0/24"},
	}
	first, err := store.AddDomain("Domain A", "", []string{"1.1.1.1"}, "corp.example", localNetworks, true, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add first: %v", err)
	}
	second, err := store.AddDomain("Domain B", "", nil, "", nil, true, time.Unix(2, 0))
	if err != nil {
		t.Fatalf("add second: %v", err)
	}

	if first.Certificate != nil || first.AutoEnrollEnabled {
		t.Fatalf("manual-only domain should not auto enroll: %+v", first)
	}
	if first.WGCIDR != "10.44.0.0/21" || first.WGServerIP != "10.44.0.1" {
		t.Fatalf("first IPv4 pool=%s gateway=%s", first.WGCIDR, first.WGServerIP)
	}
	if second.WGCIDR != "10.44.8.0/21" || second.WGServerIP != "10.44.8.1" {
		t.Fatalf("second IPv4 pool=%s gateway=%s", second.WGCIDR, second.WGServerIP)
	}
	if first.WGIPv6CIDR == second.WGIPv6CIDR {
		t.Fatalf("IPv6 pools should differ: %s", first.WGIPv6CIDR)
	}
	if len(first.DNSServers) != 1 || first.DNSServers[0] != "1.1.1.1" || first.SearchDomain != "corp.example" {
		t.Fatalf("domain DNS mismatch: %+v", first)
	}
	if len(first.LocalNetworks) != 2 || first.LocalNetworks[0].Name != "Headquarters Wi-Fi" || first.LocalNetworks[0].SSID != "Corp Wi-Fi" || first.LocalNetworks[0].Subnet != "192.168.10.0/24" || first.LocalNetworks[0].SearchDomain != "corp.example" || first.LocalNetworks[1].Gateway != "10.10.0.1" {
		t.Fatalf("local networks mismatch: %+v", first.LocalNetworks)
	}

	interfaceSettings, err := DomainInterfaceSettings(store.Domains(), VPNSettings{WGCIDR: "10.99.0.0/24", WGServerIP: "10.99.0.1", WGIPv6CIDR: "fd99::/64", WGIPv6ServerIP: "fd99::1"})
	if err != nil {
		t.Fatalf("interface settings: %v", err)
	}
	if len(interfaceSettings.ClientIPv4CIDRs) != 2 {
		t.Fatalf("interface IPv4 pools=%v", interfaceSettings.ClientIPv4CIDRs)
	}
}

func TestRootStoreMigratesLegacyLocalNetworkToProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	legacyJSON := `{"version":2,"domains":{"domain-1":{"id":"domain-1","name":"Legacy","pool_index":0,"local_network":{"wifi_name":"Corp Wi-Fi","wifi_subnet":"192.168.10.12/24","eth_gateway":"10.10.0.1"}}}}`
	if err := os.WriteFile(path, []byte(legacyJSON), 0o600); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}
	store, err := OpenRootStore(path, nil, testVPNSettings())
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	domains := store.Domains()
	if len(domains) != 1 {
		t.Fatalf("domains=%+v", domains)
	}
	profiles := domains[0].LocalNetworks
	if len(profiles) != 2 {
		t.Fatalf("profiles=%+v", profiles)
	}
	if profiles[0].Type != "wifi" || profiles[0].SSID != "Corp Wi-Fi" || profiles[0].Subnet != "192.168.10.0/24" {
		t.Fatalf("migrated Wi-Fi profile=%+v", profiles[0])
	}
	if profiles[1].Type != "ethernet" || profiles[1].Gateway != "10.10.0.1" {
		t.Fatalf("migrated Ethernet profile=%+v", profiles[1])
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated store: %v", err)
	}
	if !strings.Contains(string(persisted), `"version": 3`) || !strings.Contains(string(persisted), `"local_networks"`) {
		t.Fatalf("migration was not persisted: %s", persisted)
	}
}

func TestAdminDomainRequestsAcceptProfileListsAndLegacyObjects(t *testing.T) {
	var create adminCreateDomainRequest
	if err := json.Unmarshal([]byte(`{"local_networks":[{"type":"wifi","ssid":"HQ"},{"type":"ethernet","gateway":"10.0.0.1"}]}`), &create); err != nil {
		t.Fatalf("decode profile list: %v", err)
	}
	canonical := create.domainLocalNetworks()
	if len(canonical) != 2 || canonical[0].SSID != "HQ" || canonical[1].Gateway != "10.0.0.1" {
		t.Fatalf("canonical profiles=%+v", canonical)
	}
	var update adminUpdateDomainRequest
	if err := json.Unmarshal([]byte(`{"local_network":{"wifi_name":"Legacy Wi-Fi","eth_subnet":"10.10.0.0/24"}}`), &update); err != nil {
		t.Fatalf("decode legacy object: %v", err)
	}
	legacy := update.domainLocalNetworks()
	if legacy == nil || len(*legacy) != 2 || (*legacy)[0].SSID != "Legacy Wi-Fi" || (*legacy)[1].Subnet != "10.10.0.0/24" {
		t.Fatalf("legacy profiles=%+v", legacy)
	}
}

func TestRootStoreRejectsMicrosoftOrganizationCA(t *testing.T) {
	store, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, VPNSettings{WGCIDR: "10.44.0.0/24", WGServerIP: "10.44.0.1", WGIPv6CIDR: "fd44:44:44::/64", WGIPv6ServerIP: "fd44:44:44::1"})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	pemData := testCAPEM(t, pkix.Name{CommonName: "MS-Organization-Access"})
	_, err = store.AddDomain("Entra", pemData, nil, "", nil, true, time.Unix(1, 0))
	if err == nil || !strings.Contains(err.Error(), "MS-Organization") {
		t.Fatalf("error=%v", err)
	}
}

func TestRootStoreDeleteKeepsDomainWhenSavingFails(t *testing.T) {
	store, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, testVPNSettings())
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomain("Domain A", "", nil, "", nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("missing"); err != ErrDomainNotFound {
		t.Fatalf("missing domain error=%v", err)
	}
	store.path = filepath.Join(t.TempDir(), "missing", "roots.json")
	if err := store.Delete(domain.ID); err == nil {
		t.Fatal("expected save error")
	}
	if _, err := store.Domain(domain.ID); err != nil {
		t.Fatalf("domain lost after failed save: %v", err)
	}
}

func testCAPEM(t *testing.T, subject pkix.Name) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Unix(1, 0)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subject, NotBefore: now, NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
