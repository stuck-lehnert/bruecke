package bruecke

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg      Config
	store    ClientRepository
	wg       WireGuard
	roots    RootRepository
	sets     SettingsRepository
	remote   RemoteSubnetRepository
	rruntime RemoteSubnetSyncer
	blogs    BootstrapLogRepository
	vevents  VPNEventRepository
	logger   Logger
	clock    Clock
	keys     WireGuardKeyGenerator
	bmu      sync.Mutex
	btoken   string
	smu      sync.Mutex
	sess     map[string]adminSession
	hmu      sync.Mutex
	hosts    map[string]enrollmentHandshake
	hids     map[string]string
}

func NewServer(cfg Config, deps ServerDependencies) *Server {
	deps = deps.withDefaults()
	return &Server{
		cfg:      cfg,
		store:    deps.Clients,
		wg:       deps.WireGuard,
		roots:    deps.Roots,
		sets:     deps.Settings,
		remote:   deps.RemoteSubnets,
		rruntime: deps.RemoteRuntime,
		blogs:    bootstrapLogRepository(cfg, deps.BootstrapLogs),
		vevents:  vpnEventRepository(cfg, deps.VPNEvents),
		logger:   deps.Logger,
		clock:    deps.Clock,
		keys:     deps.KeyGenerator,
		sess:     map[string]adminSession{},
		hosts:    map[string]enrollmentHandshake{},
		hids:     map[string]string{},
	}
}

func (s *Server) now() time.Time {
	return s.clock.Now()
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/enroll/start", s.handleEnrollStart)
	mux.HandleFunc("/enroll/finish", s.handleEnrollFinish)
	mux.HandleFunc("/api/bootstrap-logs", s.handleBootstrapLogs)
	mux.HandleFunc("/api/vpn-events", s.handleVPNEvents)
	mux.HandleFunc("/api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", s.requireAdmin(s.handleAdminLogout))
	mux.HandleFunc("/api/admin/session", s.handleAdminSession)
	mux.HandleFunc("/api/admin/clients", s.requireAdmin(s.handleAdminClients))
	mux.HandleFunc("/api/admin/clients/ws", s.requireAdmin(s.handleAdminClientsWebSocket))
	mux.HandleFunc("/api/admin/manual-enroll", s.requireAdmin(s.handleAdminManualEnroll))
	mux.HandleFunc("/api/admin/windows-bootstrap.ps1", s.requireAdmin(s.handleAdminWindowsBootstrap))
	mux.HandleFunc("/api/admin/bootstrap-logs/runs", s.requireAdmin(s.handleAdminBootstrapLogRuns))
	mux.HandleFunc("/api/admin/bootstrap-logs/runs/", s.requireAdmin(s.handleAdminBootstrapLogRun))
	mux.HandleFunc("/api/admin/vpn-events", s.requireAdmin(s.handleAdminVPNEvents))
	mux.HandleFunc("/api/admin/clients/", s.requireAdmin(s.handleAdminClient))
	mux.HandleFunc("/api/admin/remote-subnets", s.requireAdmin(s.handleAdminRemoteSubnets))
	mux.HandleFunc("/api/admin/remote-subnets/", s.requireAdmin(s.handleAdminRemoteSubnet))
	mux.HandleFunc("/api/admin/groups", s.requireAdmin(s.handleAdminGroups))
	mux.HandleFunc("/api/admin/groups/", s.requireAdmin(s.handleAdminGroup))
	mux.HandleFunc("/api/admin/domains", s.requireAdmin(s.handleAdminDomains))
	mux.HandleFunc("/api/admin/domains/", s.requireAdmin(s.handleAdminDomain))
	mux.HandleFunc("/", s.handleSPA)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	index := filepath.Join(s.cfg.WebDir, "index.html")
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean != "." {
		candidate := filepath.Join(s.cfg.WebDir, clean)
		if strings.HasPrefix(candidate, filepath.Clean(s.cfg.WebDir)+string(os.PathSeparator)) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				http.ServeFile(w, r, candidate)
				return
			}
		}
	}

	if _, err := os.Stat(index); err != nil {
		http.Error(w, "admin UI is not built", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, index)
}

func hostnameFromCertificate(cert *x509.Certificate) (string, error) {
	for _, name := range cert.DNSNames {
		hostname, err := normalizeHostname(name)
		if err == nil {
			return hostname, nil
		}
	}
	if cert.Subject.CommonName != "" {
		return normalizeHostname(cert.Subject.CommonName)
	}
	return "", fmt.Errorf("client certificate has no DNS SAN or common name")
}

func normalizeHostname(raw string) (string, error) {
	hostname := strings.TrimSpace(raw)
	hostname = strings.TrimSuffix(hostname, ".")
	hostname = strings.ToLower(hostname)
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	if len(hostname) > 253 {
		return "", fmt.Errorf("hostname is too long")
	}
	if strings.Contains(hostname, "..") {
		return "", fmt.Errorf("hostname contains empty label")
	}
	for _, char := range hostname {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.' {
			continue
		}
		return "", fmt.Errorf("hostname contains invalid character")
	}
	return hostname, nil
}

func (s *Server) renderClientConfig(privateKey string, client Client) string {
	settings := s.effectiveClientSettings(client)
	var builder strings.Builder
	fmt.Fprintf(&builder, "[Interface]\n")
	fmt.Fprintf(&builder, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&builder, "Address = %s\n", clientAddressLine(client))
	dns := dnsConfigLine(settings)
	if dns != "" {
		fmt.Fprintf(&builder, "DNS = %s\n", dns)
	}
	fmt.Fprintf(&builder, "\n[Peer]\n")
	fmt.Fprintf(&builder, "PublicKey = %s\n", s.cfg.WGServerPublicKey)
	fmt.Fprintf(&builder, "Endpoint = %s\n", s.cfg.WGEndpoint)
	fmt.Fprintf(&builder, "AllowedIPs = %s\n", s.cfg.WGClientAllowedIPs)
	if s.cfg.WGPersistentKeepalive > 0 {
		fmt.Fprintf(&builder, "PersistentKeepalive = %d\n", s.cfg.WGPersistentKeepalive)
	}
	return builder.String()
}

func (s *Server) dnsConfigLine() string {
	return dnsConfigLine(s.baseVPNSettings())
}

func (s *Server) baseVPNSettings() VPNSettings {
	var settings VPNSettings
	if s.sets != nil {
		settings = s.sets.Get()
	} else {
		settings = SeedVPNSettings(s.cfg)
	}
	return settings
}

func (s *Server) domain(id string) (Domain, error) {
	if s.roots == nil {
		return Domain{}, fmt.Errorf("domain store is not configured")
	}
	return s.roots.Domain(id)
}

func (s *Server) effectiveClientSettings(client Client) VPNSettings {
	if domain, err := s.domain(client.DomainID); err == nil {
		return domain.VPNSettings()
	}
	return s.baseVPNSettings()
}

func dnsConfigLine(settings VPNSettings) string {
	entries := append([]string(nil), settings.DNSServers...)
	if settings.SearchDomain != "" {
		entries = append(entries, settings.SearchDomain)
	}
	return strings.Join(entries, ", ")
}
