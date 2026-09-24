package bruecke

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingDeleteWireGuard struct {
	testWireGuard
	publicKey string
	allowedIP string
	enabled   bool
}

func (w *recordingDeleteWireGuard) SetPeer(_ context.Context, publicKey, allowedIP string, enabled bool) error {
	w.publicKey = publicKey
	w.allowedIP = allowedIP
	w.enabled = enabled
	return nil
}

type recordingRemoteSyncer struct {
	specs   []RemoteSubnetSpec
	clients []Client
}

func (s *recordingRemoteSyncer) Sync(_ context.Context, specs []RemoteSubnetSpec, clients []Client) error {
	s.specs = append([]RemoteSubnetSpec(nil), specs...)
	s.clients = append([]Client(nil), clients...)
	return nil
}

func TestHostnameFromCertificateUsesDNSName(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"PC1.EXAMPLE.COM."},
		Subject:  pkix.Name{CommonName: "ignored.example.com"},
	}

	hostname, err := hostnameFromCertificate(cert)
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	if hostname != "pc1.example.com" {
		t.Fatalf("hostname=%q", hostname)
	}
}

func TestHostnameFromCertificateFallsBackToCommonName(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "PC2"}}

	hostname, err := hostnameFromCertificate(cert)
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	if hostname != "pc2" {
		t.Fatalf("hostname=%q", hostname)
	}
}

func TestNormalizeHostnameRejectsInvalidCharacters(t *testing.T) {
	if _, err := normalizeHostname("pc 1.example.com"); err == nil {
		t.Fatalf("expected invalid hostname error")
	}
}

func TestHandshakeStartReplacesExistingHostname(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	server := NewServer(Config{}, ServerDependencies{Clock: ClockFunc(func() time.Time { return now })})

	server.storeHandshake(enrollmentHandshake{ID: "old", Hostname: "pc1", ExpiresAt: now.Add(enrollmentTTL)})
	server.storeHandshake(enrollmentHandshake{ID: "new", Hostname: "pc1", ExpiresAt: now.Add(enrollmentTTL)})

	if _, ok := server.takeHandshake("old"); ok {
		t.Fatalf("old handshake should be cancelled")
	}
	if handshake, ok := server.takeHandshake("new"); !ok || handshake.ID != "new" {
		t.Fatalf("new handshake missing")
	}
}

func TestHandshakeExpires(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	server := NewServer(Config{}, ServerDependencies{Clock: ClockFunc(func() time.Time { return now })})
	server.storeHandshake(enrollmentHandshake{ID: "h1", Hostname: "pc1", ExpiresAt: now.Add(enrollmentTTL)})

	now = now.Add(enrollmentTTL + time.Second)
	if _, ok := server.takeHandshake("h1"); ok {
		t.Fatalf("expired handshake should be gone")
	}
}

func TestAdminDeleteClientRemovesPeerAndAssignments(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	client, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-a", DomainName: "Domain A", Settings: testVPNSettings(), PublicKey: "pub1", IssuedAt: time.Unix(1, 0)}, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	group, err := store.AddGroup("Ops", time.Unix(2, 0))
	if err != nil {
		t.Fatalf("add group: %v", err)
	}
	clientIDs := []string{client.ID}
	if _, err := store.UpdateGroup(group.ID, nil, &clientIDs, nil); err != nil {
		t.Fatalf("assign group: %v", err)
	}
	remote, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote-subnets.json"))
	if err != nil {
		t.Fatalf("open remote subnet store: %v", err)
	}
	remoteSubnet, err := remote.Add("Site", "ovpn", "site.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, []string{client.ID}, nil, time.Unix(3, 0))
	if err != nil {
		t.Fatalf("add remote subnet: %v", err)
	}
	wg := &recordingDeleteWireGuard{}
	runtime := &recordingRemoteSyncer{}
	app := NewServer(Config{}, ServerDependencies{Clients: store, WireGuard: wg, RemoteSubnets: remote, RemoteRuntime: runtime})
	app.sess["token"] = adminSession{ExpiresAt: time.Now().Add(time.Hour)}

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/clients/"+client.ID, nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "token"})
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if wg.publicKey != "pub1" || wg.allowedIP != "10.44.0.2/32,fd44:44:44::2/128" || wg.enabled {
		t.Fatalf("wireguard call=%+v", wg)
	}
	if _, err := store.Client(client.ID); err == nil {
		t.Fatalf("client still exists")
	}
	for _, view := range store.Groups(nil) {
		if view.ID == group.ID && containsID(view.ClientIDs, client.ID) {
			t.Fatalf("group still has client: %+v", view)
		}
	}
	views := remote.Subnets()
	if len(views) != 1 || views[0].ID != remoteSubnet.ID || containsID(views[0].ClientIDs, client.ID) {
		t.Fatalf("remote subnet assignments=%+v", views)
	}
	if len(runtime.clients) != 0 {
		t.Fatalf("synced clients=%+v", runtime.clients)
	}
	if len(runtime.specs) != 1 || containsID(runtime.specs[0].ClientIDs, client.ID) {
		t.Fatalf("synced specs=%+v", runtime.specs)
	}
}

func TestIssueClientConfigReturnsDomainLocalNetwork(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	roots, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, testVPNSettings())
	if err != nil {
		t.Fatalf("open roots: %v", err)
	}
	domain, err := roots.AddDomain("Domain A", "", nil, "", []DomainLocalNetwork{{Type: "ethernet", Gateway: "10.10.0.1", Subnet: "10.10.0.0/24"}}, false, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("add domain: %v", err)
	}
	app := NewServer(Config{WGServerPublicKey: "server", WGEndpoint: "vpn.example.com:51820"}, ServerDependencies{Clients: store, Roots: roots, WireGuard: testWireGuard{}})

	_, config, localNetworks, err := app.issueClientConfig(context.Background(), Enrollment{Hostname: "pc1", DomainID: domain.ID, PublicKey: "pub1"}, "private1")
	if err != nil {
		t.Fatalf("issue config: %v", err)
	}
	if !strings.Contains(config, "PrivateKey = private1") {
		t.Fatalf("config missing private key:\n%s", config)
	}
	if len(localNetworks) != 1 || localNetworks[0].Gateway != "10.10.0.1" || localNetworks[0].Subnet != "10.10.0.0/24" {
		t.Fatalf("local networks=%+v", localNetworks)
	}
}
