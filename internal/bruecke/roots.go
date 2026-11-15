package bruecke

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrRootCertificateNotFound = errors.New("root certificate not found")
var ErrDomainNotFound = errors.New("domain not found")

type RootState struct {
	Version      int                        `json:"version"`
	Certificates map[string]RootCertificate `json:"certificates,omitempty"`
	Domains      map[string]Domain          `json:"domains,omitempty"`
}

type Domain struct {
	ID                string               `json:"id"`
	Name              string               `json:"name"`
	PoolIndex         int                  `json:"pool_index"`
	WGCIDR            string               `json:"wg_cidr"`
	WGServerIP        string               `json:"wg_server_ip"`
	WGIPv6CIDR        string               `json:"wg_ipv6_cidr"`
	WGIPv6ServerIP    string               `json:"wg_ipv6_server_ip"`
	DNSServers        []string             `json:"dns_servers,omitempty"`
	SearchDomain      string               `json:"search_domain,omitempty"`
	LocalNetworks     []DomainLocalNetwork `json:"local_networks,omitempty"`
	AutoEnrollEnabled bool                 `json:"auto_enroll_enabled"`
	Certificate       *RootCertificate     `json:"certificate,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

type DomainPatch struct {
	Name              *string
	DNSServers        *[]string
	SearchDomain      *string
	LocalNetworks     *[]DomainLocalNetwork
	AutoEnrollEnabled *bool
	PEM               *string
}

type RootCertificate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	PEM       string    `json:"pem"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RootStore struct {
	mu       sync.Mutex
	path     string
	state    RootState
	seed     VPNSettings
	nextPool int
}

func OpenRootStore(path string, seedFiles []string, seed VPNSettings) (*RootStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create root store dir: %w", err)
	}
	normalizedSeed, err := normalizeVPNSettings(seed)
	if err != nil {
		return nil, err
	}

	store := &RootStore{
		path: path,
		seed: normalizedSeed,
		state: RootState{
			Version:      3,
			Certificates: map[string]RootCertificate{},
			Domains:      map[string]Domain{},
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read root store: %w", err)
		}
		for _, seedFile := range seedFiles {
			pemData, err := os.ReadFile(seedFile)
			if err != nil {
				continue
			}
			if _, err := store.addDomainLocked(filepath.Base(seedFile), string(pemData), normalizedSeed.DNSServers, normalizedSeed.SearchDomain, nil, true, time.Now().UTC()); err != nil {
				return nil, fmt.Errorf("seed root CA %s: %w", seedFile, err)
			}
		}
		if len(store.state.Domains) > 0 {
			if err := store.saveLocked(); err != nil {
				return nil, err
			}
		}
		return store, nil
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode root store: %w", err)
	}
	if store.state.Certificates == nil {
		store.state.Certificates = map[string]RootCertificate{}
	}
	if store.state.Domains == nil {
		store.state.Domains = map[string]Domain{}
	}
	loadedVersion := store.state.Version
	if err := store.migrateLocked(time.Now().UTC()); err != nil {
		return nil, err
	}
	if loadedVersion < store.state.Version {
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *RootStore) Domains() []Domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	domains := make([]Domain, 0, len(s.state.Domains))
	for _, domain := range s.state.Domains {
		domains = append(domains, copyDomain(domain))
	}
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Name < domains[j].Name
	})
	return domains
}

func (s *RootStore) Domain(id string) (Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.state.Domains[strings.TrimSpace(id)]
	if !ok {
		return Domain{}, ErrDomainNotFound
	}
	return copyDomain(domain), nil
}

func (s *RootStore) AddDomain(name, pemData string, dns []string, searchDomain string, localNetworks []DomainLocalNetwork, autoEnroll bool, now time.Time) (Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain, err := s.addDomainLocked(name, pemData, dns, searchDomain, localNetworks, autoEnroll, now)
	if err != nil {
		return Domain{}, err
	}
	if err := s.saveLocked(); err != nil {
		delete(s.state.Domains, domain.ID)
		return Domain{}, err
	}
	return copyDomain(domain), nil
}

func (s *RootStore) UpdateDomain(id string, patch DomainPatch) (Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain, ok := s.state.Domains[strings.TrimSpace(id)]
	if !ok {
		return Domain{}, ErrDomainNotFound
	}
	previous := domain
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return Domain{}, fmt.Errorf("name is required")
		}
		domain.Name = name
	}
	if patch.DNSServers != nil {
		normalized, err := normalizeDomainDNS(*patch.DNSServers, domain.SearchDomain, domain)
		if err != nil {
			return Domain{}, err
		}
		domain.DNSServers = normalized.DNSServers
	}
	if patch.SearchDomain != nil {
		normalized, err := normalizeDomainDNS(domain.DNSServers, *patch.SearchDomain, domain)
		if err != nil {
			return Domain{}, err
		}
		domain.SearchDomain = normalized.SearchDomain
	}
	if patch.LocalNetworks != nil {
		localNetworks, err := normalizeDomainLocalNetworks(*patch.LocalNetworks)
		if err != nil {
			return Domain{}, err
		}
		domain.LocalNetworks = localNetworks
	}
	if patch.PEM != nil && strings.TrimSpace(*patch.PEM) != "" {
		certs, err := certificatesFromPEM(strings.TrimSpace(*patch.PEM), domain.Name, s.nowUTC())
		if err != nil {
			return Domain{}, err
		}
		domain.Certificate = &certs[0]
	}
	if patch.AutoEnrollEnabled != nil {
		domain.AutoEnrollEnabled = *patch.AutoEnrollEnabled
	}
	if domain.Certificate == nil {
		domain.AutoEnrollEnabled = false
	}
	domain.UpdatedAt = s.nowUTC()
	s.state.Domains[domain.ID] = domain
	if err := s.saveLocked(); err != nil {
		s.state.Domains[domain.ID] = previous
		return Domain{}, err
	}
	return copyDomain(domain), nil
}

func (s *RootStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	domain, ok := s.state.Domains[id]
	if !ok {
		return ErrDomainNotFound
	}
	delete(s.state.Domains, id)
	if err := s.saveLocked(); err != nil {
		s.state.Domains[id] = domain
		return err
	}
	return nil
}

func (s *RootStore) EnabledPool() (*x509.CertPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pool := x509.NewCertPool()
	loaded := 0
	for _, domain := range s.state.Domains {
		if !domain.AutoEnrollEnabled || domain.Certificate == nil {
			continue
		}
		certs, err := parseCertificates([]byte(domain.Certificate.PEM))
		if err != nil {
			return nil, fmt.Errorf("parse domain %s CA: %w", domain.ID, err)
		}
		for _, cert := range certs {
			if isMicrosoftOrganizationCertificate(cert) {
				continue
			}
			pool.AddCert(cert)
			loaded++
		}
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no enabled root certificates")
	}
	return pool, nil
}

func (s *RootStore) VerifyClientCertificate(cert *x509.Certificate, chain []*x509.Certificate, now time.Time) (Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	intermediates := x509.NewCertPool()
	for _, intermediate := range chain {
		intermediates.AddCert(intermediate)
	}
	for _, domain := range s.state.Domains {
		if !domain.AutoEnrollEnabled || domain.Certificate == nil {
			continue
		}
		certs, err := parseCertificates([]byte(domain.Certificate.PEM))
		if err != nil {
			return Domain{}, fmt.Errorf("parse domain %s CA: %w", domain.ID, err)
		}
		pool := x509.NewCertPool()
		for _, rootCert := range certs {
			if isMicrosoftOrganizationCertificate(rootCert) {
				continue
			}
			pool.AddCert(rootCert)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			return copyDomain(domain), nil
		}
	}
	return Domain{}, fmt.Errorf("client certificate was not verified")
}

func (s *RootStore) addDomainLocked(name, pemData string, dns []string, searchDomain string, localNetworks []DomainLocalNetwork, autoEnroll bool, now time.Time) (Domain, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Domain"
	}
	poolIndex := s.nextPool
	s.nextPool++
	settings, err := generatedDomainSettings(s.seed, poolIndex, dns, searchDomain)
	if err != nil {
		return Domain{}, err
	}
	localNetworks, err = normalizeDomainLocalNetworks(localNetworks)
	if err != nil {
		return Domain{}, err
	}
	now = now.UTC()
	domain := Domain{ID: randomID("domain"), Name: name, PoolIndex: poolIndex, WGCIDR: settings.WGCIDR, WGServerIP: settings.WGServerIP, WGIPv6CIDR: settings.WGIPv6CIDR, WGIPv6ServerIP: settings.WGIPv6ServerIP, DNSServers: settings.DNSServers, SearchDomain: settings.SearchDomain, LocalNetworks: localNetworks, CreatedAt: now, UpdatedAt: now}
	if strings.TrimSpace(pemData) != "" {
		certs, err := certificatesFromPEM(pemData, name, now)
		if err != nil {
			return Domain{}, err
		}
		cert := certs[0]
		domain.ID = cert.ID
		domain.Certificate = &cert
		domain.AutoEnrollEnabled = autoEnroll
	}
	s.state.Domains[domain.ID] = domain
	return domain, nil
}

func certificatesFromPEM(pemData, name string, now time.Time) ([]RootCertificate, error) {
	certs, err := parseCertificates([]byte(pemData))
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	roots := make([]RootCertificate, 0, len(certs))
	for _, cert := range certs {
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate %s is not a CA", cert.Subject.String())
		}
		if isMicrosoftOrganizationCertificate(cert) {
			return nil, fmt.Errorf("Microsoft Entra MS-Organization certificates are not valid domain CAs")
		}
		id := certificateID(cert)
		createdAt := now.UTC()
		root := RootCertificate{
			ID:        id,
			Name:      name,
			PEM:       pemForCertificate(cert),
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			Serial:    cert.SerialNumber.String(),
			NotBefore: cert.NotBefore.UTC(),
			NotAfter:  cert.NotAfter.UTC(),
			Enabled:   false,
			CreatedAt: createdAt,
			UpdatedAt: now.UTC(),
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func isMicrosoftOrganizationCertificate(cert *x509.Certificate) bool {
	identity := strings.ToLower(cert.Subject.String() + " " + cert.Issuer.String())
	return strings.Contains(identity, "ms-organization")
}

func (s *RootStore) migrateLocked(now time.Time) error {
	if len(s.state.Domains) == 0 && len(s.state.Certificates) > 0 {
		certs := make([]RootCertificate, 0, len(s.state.Certificates))
		for _, cert := range s.state.Certificates {
			certs = append(certs, cert)
		}
		sort.Slice(certs, func(i, j int) bool { return certs[i].Subject < certs[j].Subject })
		for _, cert := range certs {
			settings, err := generatedDomainSettings(s.seed, s.nextPool, s.seed.DNSServers, s.seed.SearchDomain)
			if err != nil {
				return err
			}
			domain := Domain{ID: cert.ID, Name: rootDisplayName(cert), PoolIndex: s.nextPool, WGCIDR: settings.WGCIDR, WGServerIP: settings.WGServerIP, WGIPv6CIDR: settings.WGIPv6CIDR, WGIPv6ServerIP: settings.WGIPv6ServerIP, DNSServers: settings.DNSServers, SearchDomain: settings.SearchDomain, AutoEnrollEnabled: cert.Enabled, Certificate: &cert, CreatedAt: cert.CreatedAt, UpdatedAt: now.UTC()}
			s.nextPool++
			s.state.Domains[domain.ID] = domain
		}
	}
	maxPool := -1
	for id, domain := range s.state.Domains {
		if domain.ID == "" {
			domain.ID = id
		}
		if strings.TrimSpace(domain.Name) == "" {
			domain.Name = domain.ID
		}
		if domain.WGCIDR == "" || domain.WGServerIP == "" || domain.WGIPv6CIDR == "" || domain.WGIPv6ServerIP == "" {
			settings, err := generatedDomainSettings(s.seed, domain.PoolIndex, domain.DNSServers, domain.SearchDomain)
			if err != nil {
				return err
			}
			domain.WGCIDR = settings.WGCIDR
			domain.WGServerIP = settings.WGServerIP
			domain.WGIPv6CIDR = settings.WGIPv6CIDR
			domain.WGIPv6ServerIP = settings.WGIPv6ServerIP
		}
		settings, err := normalizeDomainDNS(domain.DNSServers, domain.SearchDomain, domain)
		if err != nil {
			return err
		}
		domain.DNSServers = settings.DNSServers
		domain.SearchDomain = settings.SearchDomain
		localNetworks, err := normalizeDomainLocalNetworks(domain.LocalNetworks)
		if err != nil {
			return err
		}
		domain.LocalNetworks = localNetworks
		if domain.Certificate == nil {
			domain.AutoEnrollEnabled = false
		}
		s.state.Domains[domain.ID] = domain
		if domain.PoolIndex > maxPool {
			maxPool = domain.PoolIndex
		}
	}
	s.nextPool = maxPool + 1
	s.state.Version = 3
	s.state.Certificates = nil
	return nil
}

func (s *RootStore) saveLocked() error {
	return writeJSONFile(s.path, "root store", s.state)
}

func certificateID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func rootDisplayName(root RootCertificate) string {
	if root.Name != "" {
		return root.Name
	}
	if root.Subject != "" {
		return root.Subject
	}
	return root.ID
}

func copyDomain(domain Domain) Domain {
	domain.DNSServers = append([]string(nil), domain.DNSServers...)
	domain.LocalNetworks = append([]DomainLocalNetwork(nil), domain.LocalNetworks...)
	if domain.Certificate != nil {
		cert := *domain.Certificate
		domain.Certificate = &cert
	}
	return domain
}

func (d Domain) VPNSettings() VPNSettings {
	return VPNSettings{
		WGCIDR:         d.WGCIDR,
		WGServerIP:     d.WGServerIP,
		WGIPv6CIDR:     d.WGIPv6CIDR,
		WGIPv6ServerIP: d.WGIPv6ServerIP,
		DNSServers:     append([]string(nil), d.DNSServers...),
		SearchDomain:   d.SearchDomain,
	}
}

func normalizeDomainDNS(dns []string, searchDomain string, domain Domain) (VPNSettings, error) {
	settings := domain.VPNSettings()
	settings.DNSServers = dns
	settings.SearchDomain = searchDomain
	return normalizeVPNSettings(settings)
}

func generatedDomainSettings(seed VPNSettings, index int, dns []string, searchDomain string) (VPNSettings, error) {
	seedNet, _, seedIPv6Net, _, err := seed.Pools()
	if err != nil {
		return VPNSettings{}, err
	}
	base4, err := ipv4ToUint(seedNet.Masked().Addr())
	if err != nil {
		return VPNSettings{}, err
	}
	base4 &= 0xffff0000
	network4 := netip.PrefixFrom(uintToIPv4(base4+uint32(index*2048)), 21).Masked()
	server4, err := firstUsableIP(network4)
	if err != nil {
		return VPNSettings{}, err
	}
	base6 := seedIPv6Net.Masked().Addr().As16()
	base6[6] = byte(index >> 8)
	base6[7] = byte(index)
	for i := 8; i < len(base6); i++ {
		base6[i] = 0
	}
	network6 := netip.PrefixFrom(netip.AddrFrom16(base6), 64).Masked()
	server6, err := firstUsableIPv6(network6)
	if err != nil {
		return VPNSettings{}, err
	}
	return normalizeVPNSettings(VPNSettings{
		WGCIDR:         network4.String(),
		WGServerIP:     server4.String(),
		WGIPv6CIDR:     network6.String(),
		WGIPv6ServerIP: server6.String(),
		DNSServers:     dns,
		SearchDomain:   searchDomain,
	})
}

func domainInterfaceSettings(domains []Domain, fallback VPNSettings) (VPNSettings, error) {
	settings := []VPNSettings{}
	for _, domain := range domains {
		settings = append(settings, domain.VPNSettings())
	}
	if len(settings) == 0 {
		settings = append(settings, fallback)
	}
	return combineInterfaceSettings(settings), nil
}

func DomainInterfaceSettings(domains []Domain, fallback VPNSettings) (VPNSettings, error) {
	return domainInterfaceSettings(domains, fallback)
}

func (s *RootStore) nowUTC() time.Time {
	return time.Now().UTC()
}
