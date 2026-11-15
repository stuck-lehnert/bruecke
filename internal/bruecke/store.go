package bruecke

import (
	"context"
	"crypto/rand"
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

var (
	ErrClientNotFound = errors.New("client not found")
	ErrClientExists   = errors.New("client or SSH public key already exists")
	ErrGroupNotFound  = errors.New("group not found")
)

const AllGroupID = "all"

type State struct {
	Version int               `json:"version"`
	Clients map[string]Client `json:"clients"`
	Groups  map[string]Group  `json:"groups,omitempty"`
}

type Client struct {
	Type                string    `json:"type,omitempty"`
	ID                  string    `json:"id"`
	Hostname            string    `json:"hostname"`
	DomainID            string    `json:"domain_id,omitempty"`
	DomainName          string    `json:"domain_name,omitempty"`
	IP                  string    `json:"ip"`
	IPv6                string    `json:"ipv6,omitempty"`
	PublicKey           string    `json:"public_key"`
	GroupIDs            []string  `json:"group_ids,omitempty"`
	RemoteSubnetIDs     []string  `json:"remote_subnet_ids,omitempty"`
	Disabled            bool      `json:"disabled,omitempty"`
	CertificateSubject  string    `json:"certificate_subject,omitempty"`
	CertificateSerial   string    `json:"certificate_serial,omitempty"`
	CertificateNotAfter time.Time `json:"certificate_not_after,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type Enrollment struct {
	Type                string
	ID                  string
	Hostname            string
	DomainID            string
	DomainName          string
	Settings            VPNSettings
	PublicKey           string
	CertificateSubject  string
	CertificateSerial   string
	CertificateNotAfter time.Time
	IssuedAt            time.Time
}

type Store struct {
	mu       sync.Mutex
	path     string
	state    State
	network  netip.Prefix
	serverIP netip.Addr
	ipv6Net  netip.Prefix
	ipv6IP   netip.Addr
}

func OpenStore(path string, network netip.Prefix, serverIP netip.Addr, ipv6Net netip.Prefix, ipv6IP netip.Addr) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	store := &Store{
		path: path,
		state: State{
			Version: 2,
			Clients: map[string]Client{},
			Groups:  map[string]Group{},
		},
		network:  network,
		serverIP: serverIP,
		ipv6Net:  ipv6Net.Masked(),
		ipv6IP:   ipv6IP,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode store: %w", err)
	}
	if store.state.Version == 0 {
		store.state.Version = 1
	}
	if store.state.Clients == nil {
		store.state.Clients = map[string]Client{}
	}
	if store.state.Groups == nil {
		store.state.Groups = map[string]Group{}
	}
	if err := store.validateLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) SetPool(network netip.Prefix, serverIP netip.Addr) error {
	return s.SetPools(network, serverIP, s.ipv6Net, s.ipv6IP)
}

func (s *Store) SetPools(network netip.Prefix, serverIP netip.Addr, ipv6Net netip.Prefix, ipv6IP netip.Addr) error {
	if !isUsableHost(network, serverIP) {
		return fmt.Errorf("server IP must be a usable host inside %s", network)
	}
	if !isUsableIPv6Host(ipv6Net, ipv6IP) {
		return fmt.Errorf("server IPv6 must be a usable host inside %s", ipv6Net)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	previousNetwork := s.network
	previousServerIP := s.serverIP
	previousIPv6Net := s.ipv6Net
	previousIPv6IP := s.ipv6IP
	s.network = network.Masked()
	s.serverIP = serverIP
	s.ipv6Net = ipv6Net.Masked()
	s.ipv6IP = ipv6IP
	if err := s.validateLocked(); err != nil {
		s.network = previousNetwork
		s.serverIP = previousServerIP
		s.ipv6Net = previousIPv6Net
		s.ipv6IP = previousIPv6IP
		return err
	}
	return nil
}

func (s *Store) Clients() []Client {
	s.mu.Lock()
	defer s.mu.Unlock()

	clients := make([]Client, 0, len(s.state.Clients))
	for _, client := range s.state.Clients {
		client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
		clients = append(clients, client)
	}
	return clients
}

func (s *Store) Client(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = s.resolveClientIDLocked(id)
	client, ok := s.state.Clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
	return client, nil
}

func (s *Store) Rotate(ctx context.Context, enrollment Enrollment, apply func(oldPublicKey, allowedIP string, enabled bool) error) (Client, error) {
	if enrollment.Type != "" && enrollment.Type != "wireguard" && enrollment.Type != "ssh" {
		return Client{}, fmt.Errorf("unknown client type")
	}
	if enrollment.Type == "ssh" {
		_, canonical, err := parseSSHPublicKey(enrollment.PublicKey)
		if err != nil {
			return Client{}, err
		}
		enrollment.PublicKey = canonical
	}
	if enrollment.Hostname == "" {
		return Client{}, fmt.Errorf("hostname is required")
	}
	if enrollment.DomainID == "" {
		return Client{}, fmt.Errorf("domain is required")
	}
	if enrollment.DomainName == "" {
		enrollment.DomainName = enrollment.DomainID
	}
	enrollment.ID = clientID(enrollment.Hostname, enrollment.DomainID)
	if enrollment.PublicKey == "" {
		return Client{}, fmt.Errorf("public key is required")
	}
	if enrollment.IssuedAt.IsZero() {
		enrollment.IssuedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	settings := enrollment.Settings
	if strings.TrimSpace(settings.WGCIDR) == "" {
		settings = VPNSettings{WGCIDR: s.network.String(), WGServerIP: s.serverIP.String(), WGIPv6CIDR: s.ipv6Net.String(), WGIPv6ServerIP: s.ipv6IP.String()}
	}
	settings, err := normalizeVPNSettings(settings)
	if err != nil {
		return Client{}, err
	}
	network, serverIP, ipv6Net, ipv6ServerIP, err := settings.Pools()
	if err != nil {
		return Client{}, err
	}

	current, known := s.state.Clients[enrollment.ID]
	if known && (current.Type == "ssh" || enrollment.Type == "ssh") {
		return Client{}, ErrClientExists
	}
	if enrollment.Type == "ssh" {
		for _, client := range s.state.Clients {
			if client.Type == "ssh" && client.PublicKey == enrollment.PublicKey {
				return Client{}, ErrClientExists
			}
		}
	}
	ip := current.IP
	ipv6 := current.IPv6
	if known {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !network.Contains(addr) || addr == serverIP {
			addr, err := allocateClientIP(network, serverIP, s.state.Clients)
			if err != nil {
				return Client{}, err
			}
			ip = addr.String()
		}
		if ipv6 != "" {
			addr, err := netip.ParseAddr(ipv6)
			if err != nil || !addr.Is6() || addr.Is4() || !ipv6Net.Contains(addr) || addr == ipv6ServerIP {
				addr, err := allocateClientIPv6(ipv6Net, ipv6ServerIP, s.state.Clients)
				if err != nil {
					return Client{}, err
				}
				ipv6 = addr.String()
			}
		}
	} else {
		addr, err := allocateClientIP(network, serverIP, s.state.Clients)
		if err != nil {
			return Client{}, err
		}
		ip = addr.String()
	}
	if ipv6 == "" {
		addr, err := allocateClientIPv6(ipv6Net, ipv6ServerIP, s.state.Clients)
		if err != nil {
			return Client{}, err
		}
		ipv6 = addr.String()
	}

	if apply != nil {
		select {
		case <-ctx.Done():
			return Client{}, ctx.Err()
		default:
		}
		if err := apply(current.PublicKey, clientAllowedIPs(Client{IP: ip, IPv6: ipv6}), !current.Disabled); err != nil {
			return Client{}, err
		}
	}

	issuedAt := enrollment.IssuedAt.UTC()
	createdAt := issuedAt
	if known && !current.CreatedAt.IsZero() {
		createdAt = current.CreatedAt
	}

	client := Client{
		Type:                enrollment.Type,
		ID:                  enrollment.ID,
		Hostname:            enrollment.Hostname,
		DomainID:            enrollment.DomainID,
		DomainName:          enrollment.DomainName,
		IP:                  ip,
		IPv6:                ipv6,
		PublicKey:           enrollment.PublicKey,
		RemoteSubnetIDs:     append([]string(nil), current.RemoteSubnetIDs...),
		Disabled:            current.Disabled,
		CertificateSubject:  enrollment.CertificateSubject,
		CertificateSerial:   enrollment.CertificateSerial,
		CertificateNotAfter: enrollment.CertificateNotAfter.UTC(),
		CreatedAt:           createdAt,
		UpdatedAt:           issuedAt,
	}

	previous := current
	s.state.Clients[enrollment.ID] = client
	if err := s.saveLocked(); err != nil {
		if known {
			s.state.Clients[enrollment.ID] = previous
		} else {
			delete(s.state.Clients, enrollment.ID)
		}
		return Client{}, err
	}

	client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
	return client, nil
}

func (s *Store) SetClientRemoteSubnetIDs(id string, ids []string) (Client, error) {
	if id == "" {
		return Client{}, fmt.Errorf("client ID is required")
	}
	normalized := normalizeRemoteSubnetIDs(ids)

	s.mu.Lock()
	defer s.mu.Unlock()

	id = s.resolveClientIDLocked(id)
	client, ok := s.state.Clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	previous := client
	client.RemoteSubnetIDs = normalized
	client.UpdatedAt = time.Now().UTC()
	s.state.Clients[id] = client
	if err := s.saveLocked(); err != nil {
		s.state.Clients[id] = previous
		return Client{}, err
	}
	client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
	return client, nil
}

func (s *Store) SetClientEnabled(ctx context.Context, id string, enabled bool, apply func(client Client) error) (Client, error) {
	if id == "" {
		return Client{}, fmt.Errorf("client ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id = s.resolveClientIDLocked(id)
	client, ok := s.state.Clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	if client.Disabled == !enabled {
		client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
		return client, nil
	}

	updated := client
	updated.Disabled = !enabled
	updated.UpdatedAt = time.Now().UTC()

	if apply != nil {
		select {
		case <-ctx.Done():
			return Client{}, ctx.Err()
		default:
		}
		if err := apply(updated); err != nil {
			return Client{}, err
		}
	}

	s.state.Clients[id] = updated
	if err := s.saveLocked(); err != nil {
		s.state.Clients[id] = client
		return Client{}, err
	}
	updated.GroupIDs = s.clientGroupIDsLocked(updated.ID, updated.DomainID)
	return updated, nil
}

func (s *Store) DeleteClient(ctx context.Context, id string, apply func(client Client) error) (Client, error) {
	if id == "" {
		return Client{}, fmt.Errorf("client ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id = s.resolveClientIDLocked(id)
	client, ok := s.state.Clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	if apply != nil {
		select {
		case <-ctx.Done():
			return Client{}, ctx.Err()
		default:
		}
		if err := apply(client); err != nil {
			return Client{}, err
		}
	}

	previousGroups := map[string]Group{}
	delete(s.state.Clients, id)
	for gid, group := range s.state.Groups {
		if !containsID(group.ClientIDs, id) {
			continue
		}
		previousGroups[gid] = group
		group.ClientIDs = removeID(group.ClientIDs, id)
		group.UpdatedAt = time.Now().UTC()
		s.state.Groups[gid] = group
	}
	if err := s.saveLocked(); err != nil {
		s.state.Clients[id] = client
		for gid, group := range previousGroups {
			s.state.Groups[gid] = group
		}
		return Client{}, err
	}
	client.GroupIDs = s.clientGroupIDsLocked(client.ID, client.DomainID)
	return client, nil
}

func (s *Store) saveLocked() error {
	return writeJSONFile(s.path, "store", s.state)
}

func (s *Store) validateLocked() error {
	seen := map[string]string{}
	seenIPv6 := map[string]string{}
	seenSSHKeys := map[string]string{}
	server := s.serverIP.String()
	serverIPv6 := s.ipv6IP.String()
	clients := map[string]Client{}
	for key, client := range s.state.Clients {
		if client.Hostname == "" {
			client.Hostname = legacyHostnameFromKey(key)
		}
		client.Hostname = strings.TrimSpace(client.Hostname)
		if client.DomainID == "" {
			return fmt.Errorf("stored client %s has no domain", client.ID)
		}
		if client.DomainName == "" {
			client.DomainName = client.DomainID
		}
		client.ID = clientID(client.Hostname, client.DomainID)
		if _, ok := clients[client.ID]; ok {
			return fmt.Errorf("duplicate stored client %s", client.ID)
		}
		addr, err := netip.ParseAddr(client.IP)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("stored IP for %s is invalid", client.ID)
		}
		if client.IP == server {
			return fmt.Errorf("stored IP for %s equals server IP", client.ID)
		}
		if other, ok := seen[client.IP]; ok {
			return fmt.Errorf("duplicate stored IP %s for %s and %s", client.IP, other, client.ID)
		}
		seen[client.IP] = client.ID
		if client.IPv6 != "" {
			addr, err := netip.ParseAddr(client.IPv6)
			if err != nil || !addr.Is6() || addr.Is4() {
				return fmt.Errorf("stored IPv6 for %s is invalid", client.ID)
			}
			if client.IPv6 == serverIPv6 {
				return fmt.Errorf("stored IPv6 for %s equals server IPv6", client.ID)
			}
			if other, ok := seenIPv6[client.IPv6]; ok {
				return fmt.Errorf("duplicate stored IPv6 %s for %s and %s", client.IPv6, other, client.ID)
			}
			seenIPv6[client.IPv6] = client.ID
		}
		if client.PublicKey == "" {
			return fmt.Errorf("stored public key for %s is empty", client.ID)
		}
		if client.Type != "" && client.Type != "wireguard" && client.Type != "ssh" {
			return fmt.Errorf("unknown stored client type for %s", client.ID)
		}
		if client.Type == "ssh" {
			_, canonical, err := parseSSHPublicKey(client.PublicKey)
			if err != nil {
				return fmt.Errorf("stored SSH key for %s: %w", client.ID, err)
			}
			client.PublicKey = canonical
			if other, ok := seenSSHKeys[canonical]; ok {
				return fmt.Errorf("duplicate SSH public key for %s and %s", other, client.ID)
			}
			seenSSHKeys[canonical] = client.ID
		}
		client.RemoteSubnetIDs = normalizeRemoteSubnetIDs(client.RemoteSubnetIDs)
		clients[client.ID] = client
	}
	s.state.Clients = clients
	if s.state.Groups == nil {
		s.state.Groups = map[string]Group{}
	}
	for id, group := range s.state.Groups {
		if group.ID == "" {
			group.ID = id
		}
		if group.Type == "" {
			group.Type = "custom"
		}
		if group.Type != "custom" {
			delete(s.state.Groups, id)
			continue
		}
		if strings.TrimSpace(group.Name) == "" {
			group.Name = group.ID
		}
		group.ClientIDs = normalizeIDs(group.ClientIDs)
		group.GroupIDs = normalizeIDs(group.GroupIDs)
		for _, clientID := range group.ClientIDs {
			if _, ok := s.state.Clients[clientID]; !ok {
				return fmt.Errorf("group %s references unknown client %s", group.ID, clientID)
			}
		}
		for _, childID := range group.GroupIDs {
			if childID == AllGroupID || childID == group.ID || !s.groupIDExistsLocked(childID, false) {
				return fmt.Errorf("group %s has invalid child group %s", group.ID, childID)
			}
		}
		s.state.Groups[group.ID] = group
	}
	for _, group := range s.state.Groups {
		if s.groupHasChildLocked(group.ID, group.ID, map[string]bool{}) {
			return fmt.Errorf("group %s is recursive", group.ID)
		}
	}
	s.state.Version = 2
	return nil
}

func containsID(ids []string, id string) bool {
	for _, item := range ids {
		if item == id {
			return true
		}
	}
	return false
}

func intersectsIDs(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

func removeID(ids []string, remove string) []string {
	// Keep the original slice intact: callers retain it for rollback on save errors.
	var next []string
	if ids != nil {
		next = make([]string, 0, len(ids))
	}
	for _, id := range ids {
		if id != remove {
			next = append(next, id)
		}
	}
	return next
}

func (s *Store) resolveClientIDLocked(id string) string {
	if _, ok := s.state.Clients[id]; ok {
		return id
	}
	var matched string
	for clientID, client := range s.state.Clients {
		if client.Hostname == id {
			if matched != "" {
				return id
			}
			matched = clientID
		}
	}
	if matched != "" {
		return matched
	}
	return id
}

func clientID(hostname, domainID string) string {
	return strings.ToLower(strings.TrimSpace(hostname)) + "|" + strings.TrimSpace(domainID)
}

func legacyHostnameFromKey(key string) string {
	if before, _, ok := strings.Cut(key, "|"); ok {
		return before
	}
	return key
}

func normalizeIDs(ids []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	return normalized
}

func randomID(prefix string) string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("%s:%d", prefix, time.Now().UnixNano())
	}
	return prefix + ":" + hex.EncodeToString(bytes[:])
}

func normalizeRemoteSubnetIDs(ids []string) []string {
	return normalizeIDs(ids)
}

func clientAddressLine(client Client) string {
	return strings.Join(clientAddresses(client), ", ")
}

func clientAllowedIPs(client Client) string {
	return strings.Join(clientAddresses(client), ",")
}

func clientAddresses(client Client) []string {
	addresses := []string{client.IP + "/32"}
	if client.IPv6 != "" {
		addresses = append(addresses, client.IPv6+"/128")
	}
	return addresses
}
