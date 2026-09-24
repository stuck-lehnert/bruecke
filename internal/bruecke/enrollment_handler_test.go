package bruecke

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateEnrollmentJSONFinishReturnsClientIdentity(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	caPEM, _, clientPEM, clientKey := testEnrollmentCertificates(t, now)

	roots, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, testVPNSettings())
	if err != nil {
		t.Fatalf("open roots: %v", err)
	}
	domain, err := roots.AddDomain("Domain A", caPEM, nil, "", []DomainLocalNetwork{{Type: "wifi", Name: "HQ Wi-Fi", SSID: "Corp Wi-Fi", Subnet: "192.168.10.0/24"}, {Type: "wifi", Name: "Branch Wi-Fi", SSID: "Branch Wi-Fi", Gateway: "192.168.20.1"}, {Type: "ethernet", Name: "HQ wired", Gateway: "10.10.0.1"}}, true, now)
	if err != nil {
		t.Fatalf("add domain: %v", err)
	}
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bruecke.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	app := NewServer(Config{WGServerPublicKey: "server", WGEndpoint: "vpn.example.com:51820"}, ServerDependencies{
		Clients:      store,
		Roots:        roots,
		WireGuard:    testWireGuard{},
		Clock:        ClockFunc(func() time.Time { return now }),
		KeyGenerator: WireGuardKeyGeneratorFunc(func() (string, string, error) { return "private1", "pub1", nil }),
	})

	startBody, err := json.Marshal(enrollStartRequest{Certificate: clientPEM})
	if err != nil {
		t.Fatalf("marshal start: %v", err)
	}
	startRec := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodPost, "/enroll/start", bytes.NewReader(startBody))
	startReq.Header.Set("Content-Type", "application/json")
	app.Routes().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", startRec.Code, startRec.Body.String())
	}
	var start enrollStartResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(start.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, clientKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	finishBody, err := json.Marshal(enrollFinishRequest{HandshakeID: start.HandshakeID, Algorithm: "sha256-rsa", Signature: base64.StdEncoding.EncodeToString(signature), ResponseFormat: "json"})
	if err != nil {
		t.Fatalf("marshal finish: %v", err)
	}
	finishRec := httptest.NewRecorder()
	finishReq := httptest.NewRequest(http.MethodPost, "/enroll/finish", bytes.NewReader(finishBody))
	finishReq.Header.Set("Content-Type", "application/json")
	app.Routes().ServeHTTP(finishRec, finishReq)
	if finishRec.Code != http.StatusOK {
		t.Fatalf("finish status=%d body=%s", finishRec.Code, finishRec.Body.String())
	}
	if got := finishRec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control=%q", got)
	}
	var finish enrollFinishResponse
	if err := json.Unmarshal(finishRec.Body.Bytes(), &finish); err != nil {
		t.Fatalf("decode finish: %v", err)
	}
	if finish.ClientID == "" || finish.Hostname != "pc1.example.com" || !strings.Contains(finish.Address, "/32") || !strings.Contains(finish.Config, "PrivateKey = private1") {
		t.Fatalf("finish response=%+v config=%q", finish, finish.Config)
	}
	if len(finish.LocalNetworks) != 3 || finish.LocalNetworks[0].SSID != "Corp Wi-Fi" || finish.LocalNetworks[1].SSID != "Branch Wi-Fi" || finish.LocalNetworks[2].Gateway != "10.10.0.1" {
		t.Fatalf("finish local networks=%+v", finish.LocalNetworks)
	}
	if finish.LocalNetwork.WifiName != "Corp Wi-Fi" || finish.LocalNetwork.EthGateway != "10.10.0.1" {
		t.Fatalf("legacy finish local network=%+v", finish.LocalNetwork)
	}
	client, err := store.Client(finish.ClientID)
	if err != nil {
		t.Fatalf("stored client: %v", err)
	}
	if client.DomainID != domain.ID || client.PublicKey != "pub1" {
		t.Fatalf("stored client=%+v domain=%s", client, domain.ID)
	}
}

func testEnrollmentCertificates(t *testing.T, now time.Time) (string, *rsa.PrivateKey, string, *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Domain A CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "pc1.example.com"},
		DNSNames:     []string{"pc1.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	clientPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	return caPEM, caKey, clientPEM, clientKey
}
