package bruecke

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type VPNSettings struct {
	WGCIDR          string   `json:"wg_cidr"`
	WGServerIP      string   `json:"wg_server_ip"`
	WGIPv6CIDR      string   `json:"wg_ipv6_cidr"`
	WGIPv6ServerIP  string   `json:"wg_ipv6_server_ip"`
	DNSServers      []string `json:"dns_servers"`
	SearchDomain    string   `json:"search_domain,omitempty"`
	AddressCIDRs    []string `json:"-"`
	ClientIPv4CIDRs []string `json:"-"`
	ClientIPv6CIDRs []string `json:"-"`
}

type SettingsStore struct {
	mu       sync.Mutex
	path     string
	settings VPNSettings
}

func OpenSettingsStore(path string, seed VPNSettings) (*SettingsStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create settings dir: %w", err)
	}

	store := &SettingsStore{path: path}
	settings, err := normalizeVPNSettings(seed)
	if err != nil {
		return nil, err
	}
	store.settings = settings

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var loaded VPNSettings
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, fmt.Errorf("decode settings: %w", err)
	}
	if strings.TrimSpace(loaded.WGCIDR) == "" {
		loaded.WGCIDR = settings.WGCIDR
	}
	if strings.TrimSpace(loaded.WGServerIP) == "" {
		loaded.WGServerIP = settings.WGServerIP
	}
	if strings.TrimSpace(loaded.WGIPv6CIDR) == "" {
		loaded.WGIPv6CIDR = settings.WGIPv6CIDR
	}
	if strings.TrimSpace(loaded.WGIPv6ServerIP) == "" {
		loaded.WGIPv6ServerIP = settings.WGIPv6ServerIP
	}
	store.settings, err = normalizeVPNSettings(loaded)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SettingsStore) Get() VPNSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyVPNSettings(s.settings)
}

func (s *SettingsStore) Set(settings VPNSettings) (VPNSettings, error) {
	normalized, err := normalizeVPNSettings(settings)
	if err != nil {
		return VPNSettings{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.settings = normalized
	if err := s.saveLocked(); err != nil {
		return VPNSettings{}, err
	}
	return copyVPNSettings(s.settings), nil
}

func (s *SettingsStore) saveLocked() error {
	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}
	data = append(data, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace settings: %w", err)
	}
	return nil
}

func SeedVPNSettings(cfg Config) VPNSettings {
	return VPNSettings{
		WGCIDR:         cfg.WGNetwork.String(),
		WGServerIP:     cfg.WGServerIP.String(),
		WGIPv6CIDR:     cfg.WGIPv6Network.String(),
		WGIPv6ServerIP: cfg.WGIPv6ServerIP.String(),
		DNSServers:     splitDNSList(cfg.WGDNSServers),
		SearchDomain:   cfg.WGSearchDomain,
	}
}

func normalizeVPNSettings(settings VPNSettings) (VPNSettings, error) {
	network, err := netip.ParsePrefix(strings.TrimSpace(settings.WGCIDR))
	if err != nil {
		return VPNSettings{}, fmt.Errorf("WireGuard CIDR: %w", err)
	}
	network = network.Masked()
	if !network.Addr().Is4() {
		return VPNSettings{}, fmt.Errorf("WireGuard CIDR must be IPv4")
	}
	if network.Bits() > 30 {
		return VPNSettings{}, fmt.Errorf("WireGuard CIDR must leave room for server and clients")
	}

	serverIP := netip.Addr{}
	if strings.TrimSpace(settings.WGServerIP) == "" {
		var err error
		serverIP, err = firstUsableIP(network)
		if err != nil {
			return VPNSettings{}, err
		}
	} else {
		var err error
		serverIP, err = netip.ParseAddr(strings.TrimSpace(settings.WGServerIP))
		if err != nil {
			return VPNSettings{}, fmt.Errorf("WireGuard server IP: %w", err)
		}
	}
	if !isUsableHost(network, serverIP) {
		return VPNSettings{}, fmt.Errorf("WireGuard server IP must be a usable host inside %s", network)
	}
	ipv6Network, err := netip.ParsePrefix(strings.TrimSpace(settings.WGIPv6CIDR))
	if err != nil {
		return VPNSettings{}, fmt.Errorf("WireGuard IPv6 CIDR: %w", err)
	}
	ipv6Network = ipv6Network.Masked()
	if !ipv6Network.Addr().Is6() || ipv6Network.Addr().Is4() {
		return VPNSettings{}, fmt.Errorf("WireGuard IPv6 CIDR must be IPv6")
	}
	if ipv6Network.Bits() >= 128 {
		return VPNSettings{}, fmt.Errorf("WireGuard IPv6 CIDR must leave room for server and clients")
	}

	ipv6ServerIP := netip.Addr{}
	if strings.TrimSpace(settings.WGIPv6ServerIP) == "" {
		var err error
		ipv6ServerIP, err = firstUsableIPv6(ipv6Network)
		if err != nil {
			return VPNSettings{}, err
		}
	} else {
		var err error
		ipv6ServerIP, err = netip.ParseAddr(strings.TrimSpace(settings.WGIPv6ServerIP))
		if err != nil {
			return VPNSettings{}, fmt.Errorf("WireGuard IPv6 server IP: %w", err)
		}
	}
	if !isUsableIPv6Host(ipv6Network, ipv6ServerIP) {
		return VPNSettings{}, fmt.Errorf("WireGuard IPv6 server IP must be a usable host inside %s", ipv6Network)
	}

	dns := make([]string, 0, len(settings.DNSServers))
	seen := map[string]struct{}{}
	for _, server := range settings.DNSServers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		addr, err := netip.ParseAddr(server)
		if err != nil {
			return VPNSettings{}, fmt.Errorf("DNS server %q is not a valid IP address", server)
		}
		server = addr.String()
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		dns = append(dns, server)
	}
	if len(dns) > 3 {
		return VPNSettings{}, fmt.Errorf("at most 3 DNS servers are allowed")
	}

	searchDomain := strings.TrimSpace(settings.SearchDomain)
	if searchDomain != "" {
		normalized, err := normalizeHostname(searchDomain)
		if err != nil {
			return VPNSettings{}, fmt.Errorf("search domain: %w", err)
		}
		searchDomain = normalized
	}

	return VPNSettings{WGCIDR: network.String(), WGServerIP: serverIP.String(), WGIPv6CIDR: ipv6Network.String(), WGIPv6ServerIP: ipv6ServerIP.String(), DNSServers: dns, SearchDomain: searchDomain}, nil
}

func copyVPNSettings(settings VPNSettings) VPNSettings {
	return VPNSettings{
		WGCIDR:          settings.WGCIDR,
		WGServerIP:      settings.WGServerIP,
		WGIPv6CIDR:      settings.WGIPv6CIDR,
		WGIPv6ServerIP:  settings.WGIPv6ServerIP,
		DNSServers:      append([]string(nil), settings.DNSServers...),
		SearchDomain:    settings.SearchDomain,
		AddressCIDRs:    append([]string(nil), settings.AddressCIDRs...),
		ClientIPv4CIDRs: append([]string(nil), settings.ClientIPv4CIDRs...),
		ClientIPv6CIDRs: append([]string(nil), settings.ClientIPv6CIDRs...),
	}
}

func combineInterfaceSettings(settings []VPNSettings) VPNSettings {
	if len(settings) == 0 {
		return VPNSettings{}
	}
	combined := copyVPNSettings(settings[0])
	seenAddress := map[string]struct{}{}
	seenV4 := map[string]struct{}{}
	seenV6 := map[string]struct{}{}
	for _, item := range settings {
		network, serverIP, ipv6Network, ipv6ServerIP, err := item.Pools()
		if err != nil {
			continue
		}
		addressV4 := fmt.Sprintf("%s/%d", serverIP, network.Bits())
		addressV6 := fmt.Sprintf("%s/%d", ipv6ServerIP, ipv6Network.Bits())
		if _, ok := seenAddress[addressV4]; !ok {
			combined.AddressCIDRs = append(combined.AddressCIDRs, addressV4)
			seenAddress[addressV4] = struct{}{}
		}
		if _, ok := seenAddress[addressV6]; !ok {
			combined.AddressCIDRs = append(combined.AddressCIDRs, addressV6)
			seenAddress[addressV6] = struct{}{}
		}
		if _, ok := seenV4[network.String()]; !ok {
			combined.ClientIPv4CIDRs = append(combined.ClientIPv4CIDRs, network.String())
			seenV4[network.String()] = struct{}{}
		}
		if _, ok := seenV6[ipv6Network.String()]; !ok {
			combined.ClientIPv6CIDRs = append(combined.ClientIPv6CIDRs, ipv6Network.String())
			seenV6[ipv6Network.String()] = struct{}{}
		}
	}
	return combined
}

func (s VPNSettings) Pool() (netip.Prefix, netip.Addr, error) {
	network, serverIP, _, _, err := s.Pools()
	return network, serverIP, err
}

func (s VPNSettings) Pools() (netip.Prefix, netip.Addr, netip.Prefix, netip.Addr, error) {
	normalized, err := normalizeVPNSettings(s)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, netip.Prefix{}, netip.Addr{}, err
	}
	network := netip.MustParsePrefix(normalized.WGCIDR)
	serverIP := netip.MustParseAddr(normalized.WGServerIP)
	ipv6Network := netip.MustParsePrefix(normalized.WGIPv6CIDR)
	ipv6ServerIP := netip.MustParseAddr(normalized.WGIPv6ServerIP)
	return network, serverIP, ipv6Network, ipv6ServerIP, nil
}

func splitDNSList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}
