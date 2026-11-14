package bruecke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func requireLinuxSSHRuntime(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("SSH runtime requires Linux network tools and file permissions")
	}
}

type sshTestAddresses struct {
	mu    sync.Mutex
	count int
}

func (a *sshTestAddresses) Add(Client) error { a.mu.Lock(); defer a.mu.Unlock(); a.count++; return nil }
func (a *sshTestAddresses) Remove(Client) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count--
	return nil
}

type sshFixture struct {
	store    *Store
	roots    *RootStore
	domain   Domain
	server   *SSHServer
	listener net.Listener
	hostKey  ssh.PublicKey
}

func newSSHFixture(t *testing.T) *sshFixture {
	t.Helper()
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "clients.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := OpenRootStore(filepath.Join(t.TempDir(), "domains.json"), nil, testVPNSettings())
	if err != nil {
		t.Fatal(err)
	}
	domain, err := roots.AddDomain("SSH test", "", nil, "example.test", nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	addresses := &sshTestAddresses{}
	hostKey := sshTestSigner(t)
	server := newSSHServer(hostKey, store, roots, nil, nil, addresses)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		addresses.mu.Lock()
		defer addresses.mu.Unlock()
		if addresses.count != 0 {
			t.Errorf("source IPs not released: %d", addresses.count)
		}
	})
	return &sshFixture{store, roots, domain, server, listener, hostKey.PublicKey()}
}

func (f *sshFixture) add(t *testing.T, hostname, kind string, signer ssh.Signer) Client {
	t.Helper()
	key := "wireguard-key-" + hostname
	if signer != nil {
		key = string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	}
	client, err := f.store.Rotate(context.Background(), Enrollment{Type: kind, Hostname: hostname, DomainID: f.domain.ID, DomainName: f.domain.Name, Settings: f.domain.VPNSettings(), PublicKey: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (f *sshFixture) connect(user string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", f.listener.Addr().String(), &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(f.hostKey), Timeout: 3 * time.Second,
	})
}

func waitSSH(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for SSH state")
}

func TestSSHPublicKeysAndAuthentication(t *testing.T) {
	keys := map[string]func() (any, error){
		"rsa2048":  func() (any, error) { return rsa.GenerateKey(rand.Reader, 2048) },
		"rsa3072":  func() (any, error) { return rsa.GenerateKey(rand.Reader, 3072) },
		"rsa4096":  func() (any, error) { return rsa.GenerateKey(rand.Reader, 4096) },
		"ecdsa256": func() (any, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
		"ecdsa384": func() (any, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
		"ecdsa521": func() (any, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) },
		"ed25519":  func() (any, error) { _, key, err := ed25519.GenerateKey(rand.Reader); return key, err },
	}
	for name, generate := range keys {
		t.Run(name, func(t *testing.T) {
			private, err := generate()
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			f := newSSHFixture(t)
			client := f.add(t, "jump", "ssh", signer)
			conn, err := f.connect(client.Hostname, signer)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return online })
			view := NewServer(Config{}, ServerDependencies{SSH: f.server}).adminClient(client, nil, time.Now())
			if view.Type != "ssh" || !view.Connected || view.SSHFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) || view.LatestHandshake == nil {
				t.Fatalf("view: %+v", view)
			}
			_ = conn.Close()
			waitSSH(t, func() bool { online, last := f.server.Status(client.ID); return !online && last != nil })
		})
	}
}

func TestSSHPublicKeyValidation(t *testing.T) {
	signer := sshTestSigner(t)
	valid := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub, err := ssh.NewPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"jump"}}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "not-a-key", "command=\"id\" " + valid, valid + "\n" + valid, string(ssh.MarshalAuthorizedKey(weakPub)), string(ssh.MarshalAuthorizedKey(cert)), strings.Repeat("x", 17000)} {
		if _, _, err := parseSSHPublicKey(raw); err == nil {
			t.Errorf("accepted invalid key %q", raw[:min(len(raw), 80)])
		}
	}
	_, canonical, err := parseSSHPublicKey(valid + " comment")
	if err != nil || canonical != valid {
		t.Fatalf("canonical key: %q %v", canonical, err)
	}
}

func TestSSHRejectsUnauthorizedAndNonForwardingChannels(t *testing.T) {
	f := newSSHFixture(t)
	signer := sshTestSigner(t)
	client := f.add(t, "jump", "ssh", signer)
	for _, attempt := range []struct {
		user string
		key  ssh.Signer
	}{{"wrong", signer}, {client.Hostname, sshTestSigner(t)}} {
		conn, err := f.connect(attempt.user, attempt.key)
		if err == nil {
			conn.Close()
			t.Fatal("unauthorized login accepted")
		}
	}
	conn, err := f.connect(client.ID, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, kind := range []string{"session", "forwarded-tcpip", "direct-streamlocal@openssh.com", "auth-agent@openssh.com", "tun@openssh.com"} {
		ch, _, err := conn.OpenChannel(kind, nil)
		if err == nil {
			ch.Close()
			t.Errorf("accepted channel %s", kind)
		}
	}
	for _, kind := range []string{"tcpip-forward", "cancel-tcpip-forward", "streamlocal-forward@openssh.com"} {
		ok, _, err := conn.SendRequest(kind, true, nil)
		if err != nil || ok {
			t.Errorf("global request %s: %v %v", kind, ok, err)
		}
	}
	if _, err := f.store.SetClientEnabled(context.Background(), client.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	f.server.Disconnect(client.ID)
	waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return !online })
	if conn, err := f.connect(client.Hostname, signer); err == nil {
		conn.Close()
		t.Fatal("disabled client accepted")
	}
	if conn, err := ssh.Dial("tcp", f.listener.Addr().String(), &ssh.ClientConfig{User: client.Hostname, Auth: []ssh.AuthMethod{ssh.Password("password")}, HostKeyCallback: ssh.FixedHostKey(f.hostKey), Timeout: time.Second}); err == nil {
		conn.Close()
		t.Fatal("password accepted")
	}
}

func TestSSHForwardingAndRevocation(t *testing.T) {
	f := newSSHFixture(t)
	signer := sshTestSigner(t)
	client := f.add(t, "jump", "ssh", signer)
	peer := f.add(t, "pc1", "", nil)
	var sourceIP string
	var mu sync.Mutex
	f.server.dial = func(ctx context.Context, source, target netip.Addr, port uint32) (net.Conn, error) {
		mu.Lock()
		sourceIP = source.String()
		mu.Unlock()
		if target.String() != peer.IP && target.String() != peer.IPv6 {
			return nil, fmt.Errorf("unexpected target")
		}
		left, right := net.Pipe()
		go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
		return left, nil
	}
	conn, err := f.connect(client.Hostname, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, host := range []string{peer.IP, peer.IPv6, "pc1", "pc1.example.test"} {
		forward, err := conn.Dial("tcp", net.JoinHostPort(host, "22"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forward.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(forward, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("echo %q %v", buf, err)
		}
		mu.Lock()
		source := sourceIP
		mu.Unlock()
		want := client.IP
		if host == peer.IPv6 {
			want = client.IPv6
		}
		if source != want {
			t.Fatalf("source=%s want %s", source, want)
		}
		forward.Close()
	}
	for _, host := range []string{"127.0.0.1", "::1", "169.254.169.254", "example.com", client.IP, f.domain.WGServerIP, "10.44.0.254", "::ffff:127.0.0.1"} {
		if forward, err := conn.Dial("tcp", net.JoinHostPort(host, "22")); err == nil {
			forward.Close()
			t.Errorf("forward allowed: %s", host)
		}
	}
	forward, err := conn.Dial("tcp", net.JoinHostPort(peer.IP, "22"))
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	if _, err := f.store.SetClientEnabled(context.Background(), peer.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := forward.Read(make([]byte, 1)); readDone <- err }()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("revoked forward still open")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked forward not closed")
	}
}

func TestSSHStoreAllocationAndPersistence(t *testing.T) {
	f := newSSHFixture(t)
	signer := sshTestSigner(t)
	client := f.add(t, "jump", "ssh", signer)
	wg := f.add(t, "pc", "", nil)
	if client.IP == wg.IP || client.IPv6 == wg.IPv6 {
		t.Fatal("IP collision")
	}
	for _, e := range []Enrollment{
		{Hostname: client.Hostname, DomainID: client.DomainID, PublicKey: "wg"},
		{Type: "ssh", Hostname: client.Hostname, DomainID: client.DomainID, PublicKey: client.PublicKey},
		{Type: "ssh", Hostname: "duplicate-key", DomainID: client.DomainID, PublicKey: client.PublicKey},
		{Type: "ssh", Hostname: wg.Hostname, DomainID: client.DomainID, PublicKey: client.PublicKey},
	} {
		if _, err := f.store.Rotate(context.Background(), e, nil); !errors.Is(err, ErrClientExists) {
			t.Fatalf("duplicate result %v", err)
		}
	}
	network, serverIP, ipv6Net, ipv6IP := testPools()
	reopened, err := OpenStore(f.store.path, network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Client(client.ID)
	if err != nil || got.Type != "ssh" || got.PublicKey != client.PublicKey || got.IP != client.IP || got.IPv6 != client.IPv6 {
		t.Fatalf("reopened %+v %v", got, err)
	}
}

func TestAdminSSHClientLifecycle(t *testing.T) {
	f := newSSHFixture(t)
	signer := sshTestSigner(t)
	wg := &recordingDeleteWireGuard{}
	app := NewServer(Config{}, ServerDependencies{Clients: f.store, Roots: f.roots, WireGuard: wg, SSH: f.server})
	app.sess["token"] = adminSession{ExpiresAt: time.Now().Add(time.Hour)}
	body, _ := json.Marshal(map[string]string{"hostname": "newjump", "domain_id": f.domain.ID, "public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))})
	request := func(method, path string, body []byte, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if authenticated {
			req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "token"})
		}
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := request("POST", "/api/admin/ssh-clients", body, false); rec.Code != 401 {
		t.Fatalf("unauth status %d", rec.Code)
	}
	rec := request("POST", "/api/admin/ssh-clients", body, true)
	if rec.Code != 201 {
		t.Fatalf("create %d: %s", rec.Code, rec.Body.String())
	}
	var client adminClient
	if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	if client.Type != "ssh" || client.SSHFingerprint == "" || client.IP == "" || client.IPv6 == "" {
		t.Fatalf("client %+v", client)
	}
	if rec := request("POST", "/api/admin/ssh-clients", body, true); rec.Code != 409 {
		t.Fatalf("duplicate %d", rec.Code)
	}
	conn, err := f.connect(client.Hostname, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return online })
	if rec := request("PATCH", "/api/admin/clients/"+client.ID, []byte(`{"enabled":false}`), true); rec.Code != 200 {
		t.Fatalf("disable %d %s", rec.Code, rec.Body)
	}
	waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return !online })
	if rec := request("DELETE", "/api/admin/clients/"+client.ID, nil, true); rec.Code != 204 {
		t.Fatalf("delete %d %s", rec.Code, rec.Body)
	}
	if wg.publicKey != "" {
		t.Fatal("SSH key sent to WireGuard")
	}
}

func TestSSHHostKeyPersistence(t *testing.T) {
	requireLinuxSSHRuntime(t)
	path := filepath.Join(t.TempDir(), "hostkey")
	first, err := loadSSHHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadSSHHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Fatal("host key changed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSHHostKey(path); err == nil {
		t.Fatal("insecure permissions accepted")
	}
}

type sshTestRemote struct {
	RemoteSubnetRepository
	specs []RemoteSubnetSpec
}

func (r *sshTestRemote) Specs() []RemoteSubnetSpec { return r.specs }

func TestSSHDestinationIsolationAndAssignments(t *testing.T) {
	f := newSSHFixture(t)
	client := f.add(t, "jump", "ssh", sshTestSigner(t))
	peer := f.add(t, "pc", "", nil)
	other, err := f.roots.AddDomain("Other domain", "", nil, "other.test", nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := f.store.Rotate(context.Background(), Enrollment{Hostname: "foreign", DomainID: other.ID, Settings: other.VPNSettings(), PublicKey: "foreign-key"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote := &sshTestRemote{specs: []RemoteSubnetSpec{{ID: "office", Enabled: true, Subnets: []string{"192.0.2.0/24"}}}}
	f.server.remote = remote
	allowed := func(ip string) bool { return f.server.allowed(client, netip.MustParseAddr(ip)) }
	if !allowed(peer.IP) || !allowed(peer.IPv6) || allowed(foreign.IP) || allowed(foreign.IPv6) || allowed("192.0.2.10") {
		t.Fatal("domain or remote isolation failed")
	}
	remote.specs[0].ClientIDs = []string{client.ID}
	if !allowed("192.0.2.10") {
		t.Fatal("assigned remote subnet denied")
	}
	remote.specs[0].Enabled = false
	if allowed("192.0.2.10") {
		t.Fatal("disabled remote subnet allowed")
	}
	remote.specs[0].Enabled = true
	remote.specs[0].ClientIDs = nil
	remote.specs[0].GroupIDs = []string{domainGroupID(client.DomainID)}
	if !allowed("192.0.2.10") {
		t.Fatal("domain group assignment denied")
	}
	remote.specs[0].Subnets = []string{"0.0.0.0/0", "::/0"}
	for _, ip := range []string{foreign.IP, foreign.IPv6, client.IP, client.IPv6, other.WGServerIP, f.domain.WGServerIP, "127.0.0.1", "169.254.169.254", "224.0.0.1", "fe80::1"} {
		if allowed(ip) {
			t.Errorf("broad route bypassed isolation for %s", ip)
		}
	}
	if _, err := f.store.SetClientEnabled(context.Background(), peer.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if allowed(peer.IP) {
		t.Fatal("disabled VPN client allowed via broad remote route")
	}
}

func TestSSHMultipleConnectionsShareSourceIPs(t *testing.T) {
	f := newSSHFixture(t)
	signer := sshTestSigner(t)
	client := f.add(t, "jump", "ssh", signer)
	var connections []*ssh.Client
	for range 4 {
		conn, err := f.connect(client.Hostname, signer)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		defer conn.Close()
	}
	waitSSH(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return len(f.server.active[client.ID]) == 4
	})
	if fifth, err := f.connect(client.Hostname, signer); err == nil {
		defer fifth.Close()
		done := make(chan error, 1)
		go func() { done <- fifth.Wait() }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("fifth connection not rejected")
		}
	}
	for _, conn := range connections[:3] {
		conn.Close()
	}
	waitSSH(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return len(f.server.active[client.ID]) == 1
	})
	if online, _ := f.server.Status(client.ID); !online {
		t.Fatal("remaining connection incorrectly offline")
	}
	connections[3].Close()
	waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return !online })
	// A pending unauthenticated handshake must not block server shutdown.
	raw, err := net.Dial("tcp", f.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := f.server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSSHOpenSSHInterop(t *testing.T) {
	requireLinuxSSHRuntime(t)
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client is not installed")
	}
	f := newSSHFixture(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	client := f.add(t, "openssh", "ssh", signer)
	peer := f.add(t, "target", "", nil)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	f.server.dial = func(ctx context.Context, source, target netip.Addr, port uint32) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(f.listener.Addr().String())
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("[127.0.0.1]:"+port+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.hostKey)))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=yes", "-p", port, "-i", keyPath}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append(base, "-W", net.JoinHostPort(peer.IP, "22"), client.Hostname+"@127.0.0.1")...)
	cmd.Stdin = strings.NewReader("openssh-forward")
	if out, err := cmd.Output(); err != nil || string(out) != "openssh-forward" {
		t.Fatalf("OpenSSH -W %q: %v", out, err)
	}
	waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return !online })
	cmd = exec.CommandContext(ctx, "ssh", append(base, client.Hostname+"@127.0.0.1", "id")...)
	if out, err := cmd.CombinedOutput(); err == nil || !bytes.Contains(out, []byte("channel")) {
		t.Fatalf("OpenSSH exec should fail at channel open: %q %v", out, err)
	}
}

func TestSSHDialerBindsSourceWithoutFallback(t *testing.T) {
	requireLinuxSSHRuntime(t)
	for _, family := range []struct{ network, listen, source string }{{"tcp4", "127.0.0.1:0", "127.0.0.2"}, {"tcp6", "[::1]:0", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			listener, err := net.Listen(family.network, family.listen)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					observed <- err.Error()
					return
				}
				defer conn.Close()
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				observed <- host
			}()
			addr := listener.Addr().(*net.TCPAddr)
			conn, err := dialSSHForward(context.Background(), netip.MustParseAddr(family.source), netip.MustParseAddr(addr.IP.String()), uint32(addr.Port))
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			select {
			case got := <-observed:
				if got != family.source {
					t.Fatalf("source=%s want %s", got, family.source)
				}
			case <-time.After(time.Second):
				t.Fatal("missing source")
			}
			unassigned := "192.0.2.222"
			if family.network == "tcp6" {
				unassigned = "2001:db8::222"
			}
			conn, err = dialSSHForward(context.Background(), netip.MustParseAddr(unassigned), netip.MustParseAddr(addr.IP.String()), uint32(addr.Port))
			if err == nil {
				conn.Close()
				t.Fatal("unassigned source fell back to host IP")
			}
		})
	}
}

func TestSSHAddressCommandsAndRollback(t *testing.T) {
	requireLinuxSSHRuntime(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands")
	t.Setenv("SSH_IP_TEST_LOG", logPath)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SSH_IP_TEST_LOG\"\nif [ \"$1 $2 $3\" = '-6 address replace' ] && [ \"${SSH_IP_TEST_FAIL:-}\" = 1 ]; then exit 1; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	client := Client{IP: "10.44.0.2", IPv6: "fd44:44:44::2"}
	if err := (sshNetwork{}).Add(client); err != nil {
		t.Fatal(err)
	}
	if err := (sshNetwork{}).Remove(client); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_IP_TEST_FAIL", "1")
	if err := (sshNetwork{}).Add(client); err == nil {
		t.Fatal("IPv6 setup failure not propagated")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "-4 address replace 10.44.0.2/32 dev br-ssh\n-6 address replace fd44:44:44::2/128 dev br-ssh nodad\n-4 address del 10.44.0.2/32 dev br-ssh\n-6 address del fd44:44:44::2/128 dev br-ssh\n-4 address replace 10.44.0.2/32 dev br-ssh\n-6 address replace fd44:44:44::2/128 dev br-ssh nodad\n-4 address del 10.44.0.2/32 dev br-ssh\n"
	if string(data) != want {
		t.Fatalf("address commands:\n%s", data)
	}
}

func TestSSHDeletedIdentityCannotInheritRecreatedClient(t *testing.T) {
	f := newSSHFixture(t)
	oldSigner := sshTestSigner(t)
	oldClient := f.add(t, "jump", "ssh", oldSigner)
	peer := f.add(t, "pc", "", nil)
	old, err := f.connect(oldClient.Hostname, oldSigner)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	waitSSH(t, func() bool { online, _ := f.server.Status(oldClient.ID); return online })
	// Simulate deletion/recreation racing with the old connection's teardown.
	if _, err := f.store.DeleteClient(context.Background(), oldClient.ID, nil); err != nil {
		t.Fatal(err)
	}
	newSigner := sshTestSigner(t)
	recreated := f.add(t, "jump", "ssh", newSigner)
	if ch, err := old.Dial("tcp", net.JoinHostPort(peer.IP, "22")); err == nil {
		ch.Close()
		t.Fatal("old key inherited the recreated identity")
	}
	if conn, err := f.connect(recreated.Hostname, newSigner); err == nil {
		defer conn.Close()
		done := make(chan error, 1)
		go func() { done <- conn.Wait() }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("new identity reused closing source-IP lease")
		}
	}
	old.Close()
	waitSSH(t, func() bool { online, _ := f.server.Status(oldClient.ID); return !online })
	conn, err := f.connect(recreated.Hostname, newSigner)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitSSH(t, func() bool { online, _ := f.server.Status(recreated.ID); return online })
}

func TestSSHClientsNeverBecomeWireGuardPeers(t *testing.T) {
	requireLinuxSSHRuntime(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "peers")
	t.Setenv("SSH_WG_TEST_LOG", logPath)
	script := filepath.Join(dir, "peer")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$SSH_WG_TEST_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	wg := NewScriptWireGuard(Config{ApplyWireGuard: true, WGInterface: "wg0", ApplyPeerScript: script, RemovePeerScript: script}, nil)
	clients := []Client{{Type: "ssh", PublicKey: "ssh-key", IP: "10.44.0.2"}, {PublicKey: "wg-enabled", IP: "10.44.0.3"}, {PublicKey: "wg-disabled", IP: "10.44.0.4", Disabled: true}}
	if err := wg.Sync(context.Background(), clients); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "wg-enabled\nwg-disabled\n" {
		t.Fatalf("WireGuard peer scripts received: %s", data)
	}
}

// Opt in inside an isolated privileged Linux network namespace. This exercises
// the real iproute2 address lifecycle and kernel TCP source binding, not mocks.
func TestSSHNetworkIntegration(t *testing.T) {
	requireLinuxSSHRuntime(t)
	if os.Getenv("BRUECKE_TEST_SSH_NETWORK") != "1" {
		t.Skip("requires isolated NET_ADMIN environment and iproute2")
	}
	if err := prepareSSHNetwork(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = sshIP("link", "delete", sshInterface) })
	f := newSSHFixture(t)
	f.server.addresses = sshNetwork{}
	signer := sshTestSigner(t)
	client := f.add(t, "jump", "ssh", signer)
	peer := f.add(t, "pc", "", nil)
	for _, family := range []struct{ network, listen, source string }{{"tcp4", "127.0.0.1:0", client.IP}, {"tcp6", "[::1]:0", client.IPv6}} {
		t.Run(family.network, func(t *testing.T) {
			listener, err := net.Listen(family.network, family.listen)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					observed <- err.Error()
					return
				}
				defer conn.Close()
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				observed <- host
				_, _ = io.Copy(conn, conn)
			}()
			// Only redirect the logical VPN target to a local test echo socket;
			// retain the production dialer's real per-client source-IP binding.
			f.server.dial = func(ctx context.Context, source, target netip.Addr, port uint32) (net.Conn, error) {
				addr := listener.Addr().(*net.TCPAddr)
				return dialSSHForward(ctx, source, netip.MustParseAddr(addr.IP.String()), uint32(addr.Port))
			}
			conn, err := f.connect(client.Hostname, signer)
			if err != nil {
				t.Fatal(err)
			}
			target := peer.IP
			if family.network == "tcp6" {
				target = peer.IPv6
			}
			forward, err := conn.Dial("tcp", net.JoinHostPort(target, "22"))
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			_, err = forward.Write([]byte("source-ip"))
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 9)
			if _, err := io.ReadFull(forward, buf); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-observed:
				if got != family.source {
					t.Fatalf("kernel saw source %s, want %s", got, family.source)
				}
			case <-time.After(time.Second):
				t.Fatal("missing source IP")
			}
			forward.Close()
			conn.Close()
			waitSSH(t, func() bool { online, _ := f.server.Status(client.ID); return !online })
		})
	}
	// Standard OpenSSH -W must work, while exec/SFTP/session channels fail.
	keyPath := filepath.Join(t.TempDir(), "client_key")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	openSigner, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	openClient := f.add(t, "openssh", "ssh", openSigner)
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(f.listener.Addr().String())
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("[127.0.0.1]:"+port+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.hostKey)))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=yes", "-p", port, "-i", keyPath}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	f.server.dial = func(ctx context.Context, source, target netip.Addr, port uint32) (net.Conn, error) {
		addr := echo.Addr().(*net.TCPAddr)
		return dialSSHForward(ctx, source, netip.MustParseAddr(addr.IP.String()), uint32(addr.Port))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append(base, "-W", net.JoinHostPort(peer.IP, "22"), openClient.Hostname+"@127.0.0.1")...)
	cmd.Stdin = strings.NewReader("openssh-forward")
	if out, err := cmd.Output(); err != nil || string(out) != "openssh-forward" {
		t.Fatalf("OpenSSH forwarding %q: %v", out, err)
	}
	waitSSH(t, func() bool { online, _ := f.server.Status(openClient.ID); return !online })
	cmd = exec.CommandContext(ctx, "ssh", append(base, openClient.Hostname+"@127.0.0.1", "id")...)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("OpenSSH exec accepted: %s", out)
	}
	waitSSH(t, func() bool { online, _ := f.server.Status(openClient.ID); return !online })
	// Confirm no allocated aliases survive the last connection.
	addrs, err := net.InterfaceByName(sshInterface)
	if err != nil {
		t.Fatal(err)
	}
	list, err := addrs.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range list {
		prefix, _ := netip.ParsePrefix(raw.String())
		if prefix.Addr().String() == client.IP || prefix.Addr().String() == client.IPv6 || prefix.Addr().String() == openClient.IP {
			t.Fatalf("source alias leaked: %s", raw)
		}
	}
}
