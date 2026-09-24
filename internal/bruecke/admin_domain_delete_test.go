package bruecke

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type recordingDomainReconfigure struct {
	testWireGuard
	calls int
	next  VPNSettings
	err   error
}

func (w *recordingDomainReconfigure) Reconfigure(_ context.Context, _, next VPNSettings, _ []Client) error {
	w.calls++
	w.next = next
	return w.err
}

func newDomainDeleteServer(t *testing.T) (*Server, *RootStore, *Store, Domain, *recordingDomainReconfigure) {
	t.Helper()
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(filepath.Join(t.TempDir(), "clients.json"), network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := OpenRootStore(filepath.Join(t.TempDir(), "roots.json"), nil, testVPNSettings())
	if err != nil {
		t.Fatal(err)
	}
	domain, err := roots.AddDomain("Domain A", "", nil, "", nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("master-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	wg := &recordingDomainReconfigure{}
	app := NewServer(Config{AdminHash: string(hash)}, ServerDependencies{Clients: store, Roots: roots, WireGuard: wg})
	app.sess["session"] = adminSession{ExpiresAt: time.Now().Add(time.Hour)}
	return app, roots, store, domain, wg
}

func requestDomainDelete(t *testing.T, app *Server, id, password string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(adminDeleteDomainRequest{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/domains/"+id, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if authenticated {
		req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "session"})
	}
	response := httptest.NewRecorder()
	app.Routes().ServeHTTP(response, req)
	return response
}

func TestAdminDeleteDomainRequiresSessionAndPassword(t *testing.T) {
	app, roots, _, domain, wg := newDomainDeleteServer(t)
	for _, test := range []struct {
		name          string
		password      string
		authenticated bool
		wantStatus    int
	}{
		{"no session", "master-password", false, http.StatusUnauthorized},
		{"no password", "", true, http.StatusUnauthorized},
		{"wrong password", "wrong", true, http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := requestDomainDelete(t, app, domain.ID, test.password, test.authenticated)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if _, err := roots.Domain(domain.ID); err != nil {
				t.Fatalf("domain was deleted: %v", err)
			}
		})
	}
	if wg.calls != 0 {
		t.Fatalf("reconfigured for rejected delete: %d", wg.calls)
	}
}

func TestAdminDeleteDomainRejectsEnrolledClients(t *testing.T) {
	app, roots, store, domain, wg := newDomainDeleteServer(t)
	_, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: domain.ID, DomainName: domain.Name, Settings: domain.VPNSettings(), PublicKey: "pub1", IssuedAt: time.Now()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := requestDomainDelete(t, app, domain.ID, "master-password", true)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "enrolled clients") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := roots.Domain(domain.ID); err != nil || wg.calls != 0 {
		t.Fatalf("domain changed after conflict: err=%v calls=%d", err, wg.calls)
	}
}

func TestAdminDeleteDomainRejectsAssignments(t *testing.T) {
	for _, kind := range []string{"group", "remote subnet"} {
		t.Run(kind, func(t *testing.T) {
			app, roots, store, domain, wg := newDomainDeleteServer(t)
			if kind == "group" {
				group, err := store.AddGroup("Ops", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				ids := []string{domainGroupID(domain.ID)}
				if _, err := store.UpdateGroup(group.ID, nil, nil, &ids); err != nil {
					t.Fatal(err)
				}
			} else {
				remote, err := OpenRemoteSubnetStore(filepath.Join(t.TempDir(), "remote.json"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := remote.Add("Site", "ovpn", "site.ovpn", "client\nremote vpn 1194", []string{"10.10.0.0/24"}, nil, []string{domainGroupID(domain.ID)}, time.Now()); err != nil {
					t.Fatal(err)
				}
				app.remote = remote
			}
			response := requestDomainDelete(t, app, domain.ID, "master-password", true)
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if _, err := roots.Domain(domain.ID); err != nil || wg.calls != 0 {
				t.Fatalf("domain changed after conflict: err=%v calls=%d", err, wg.calls)
			}
		})
	}
}

func TestAdminDeleteDomainRemovesEmptyDomain(t *testing.T) {
	app, roots, _, domain, wg := newDomainDeleteServer(t)
	response := requestDomainDelete(t, app, domain.ID, "master-password", true)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := roots.Domain(domain.ID); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("domain still present: %v", err)
	}
	if wg.calls != 1 || len(wg.next.ClientIPv4CIDRs) != 0 {
		t.Fatalf("WireGuard not reconfigured: calls=%d next=%+v", wg.calls, wg.next)
	}
	if response := requestDomainDelete(t, app, domain.ID, "master-password", true); response.Code != http.StatusNotFound {
		t.Fatalf("second delete status=%d", response.Code)
	}
}

func TestAdminDeleteDomainKeepsDomainWhenReconfigureFails(t *testing.T) {
	app, roots, _, domain, wg := newDomainDeleteServer(t)
	wg.err = errors.New("apply failed")
	response := requestDomainDelete(t, app, domain.ID, "master-password", true)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := roots.Domain(domain.ID); err != nil {
		t.Fatalf("domain was deleted: %v", err)
	}
}

func TestAdminDeleteDomainRestoresWireGuardWhenSavingFails(t *testing.T) {
	app, roots, _, domain, wg := newDomainDeleteServer(t)
	roots.path = filepath.Join(t.TempDir(), "missing", "roots.json")
	response := requestDomainDelete(t, app, domain.ID, "master-password", true)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := roots.Domain(domain.ID); err != nil {
		t.Fatalf("domain was deleted: %v", err)
	}
	if wg.calls != 2 {
		t.Fatalf("WireGuard rollback calls=%d, want 2", wg.calls)
	}
}
