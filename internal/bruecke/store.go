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

var ErrClientNotFound = errors.New("client not found")
var ErrGroupNotFound = errors.New("group not found")

const (
	AllGroupID = "all"
)

type State struct {
	Version int               `json:"version"`
	Clients map[string]Client `json:"clients"`
	Groups  map[string]Group  `json:"groups,omitempty"`
}

type Client struct {
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

type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	ClientIDs []string  `json:"client_ids,omitempty"`
	GroupIDs  []string  `json:"group_ids,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type GroupView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	ClientIDs []string  `json:"client_ids,omitempty"`
	GroupIDs  []string  `json:"group_ids,omitempty"`
	BuiltIn   bool      `json:"built_in"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type Enrollment struct {
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

func (s *Store) Groups(domains []Domain) []GroupView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.groupViewsLocked(domains)
}

func (s *Store) NormalizeAssignmentReferences(clientIDs, groupIDs []string) ([]string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalizedClients := make([]string, 0, len(clientIDs))
	for _, id := range normalizeIDs(clientIDs) {
		resolved := s.resolveClientIDLocked(id)
		if _, ok := s.state.Clients[resolved]; !ok {
			return nil, nil, fmt.Errorf("unknown client %s", id)
		}
		normalizedClients = append(normalizedClients, resolved)
	}
	normalizedClients = normalizeIDs(normalizedClients)

	normalizedGroups := normalizeIDs(groupIDs)
	for _, id := range normalizedGroups {
		if !s.groupIDExistsLocked(id, true) {
			return nil, nil, fmt.Errorf("unknown group %s", id)
		}
	}
	return normalizedClients, normalizedGroups, nil
}

func (s *Store) AddGroup(name string, now time.Time) (GroupView, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return GroupView{}, fmt.Errorf("name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randomID("custom")
	group := Group{ID: id, Name: name, Type: "custom", CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	s.state.Groups[id] = group
	if err := s.saveLocked(); err != nil {
		delete(s.state.Groups, id)
		return GroupView{}, err
	}
	return groupView(group, false), nil
}

func (s *Store) UpdateGroup(id string, name *string, clientIDs, groupIDs *[]string) (GroupView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.state.Groups[id]
	if !ok || group.Type != "custom" {
		return GroupView{}, ErrGroupNotFound
	}
	previous := group
	if name != nil {
		trimmed := strings.TrimSpace(*name)
		if trimmed == "" {
			return GroupView{}, fmt.Errorf("name is required")
		}
		group.Name = trimmed
	}
	if clientIDs != nil {
		ids := normalizeIDs(*clientIDs)
		for _, clientID := range ids {
			if _, ok := s.state.Clients[clientID]; !ok {
				return GroupView{}, fmt.Errorf("unknown client %s", clientID)
			}
		}
		group.ClientIDs = ids
	}
	if groupIDs != nil {
		ids := normalizeIDs(*groupIDs)
		for _, childID := range ids {
			if childID == AllGroupID || childID == id || !s.groupIDExistsLocked(childID, false) {
				return GroupView{}, fmt.Errorf("invalid child group %s", childID)
			}
		}
		group.GroupIDs = ids
	}
	group.UpdatedAt = time.Now().UTC()
	s.state.Groups[id] = group
	if s.groupHasChildLocked(id, id, map[string]bool{}) {
		s.state.Groups[id] = previous
		return GroupView{}, fmt.Errorf("recursive group relationship")
	}
	if err := s.saveLocked(); err != nil {
		s.state.Groups[id] = previous
		return GroupView{}, err
	}
	return groupView(group, false), nil
}

func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.state.Groups[id]
	if !ok || group.Type != "custom" {
		return ErrGroupNotFound
	}
	delete(s.state.Groups, id)
	for gid, item := range s.state.Groups {
		item.GroupIDs = removeID(item.GroupIDs, id)
		s.state.Groups[gid] = item
	}
	if err := s.saveLocked(); err != nil {
		s.state.Groups[id] = group
		return err
	}
	return nil
}

func (s *Store) Rotate(ctx context.Context, enrollment Enrollment, apply func(oldPublicKey, allowedIP string, enabled bool) error) (Client, error) {
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
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode store: %w", err)
	}
	data = append(data, '\n')

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace store: %w", err)
	}
	return nil
}

func (s *Store) validateLocked() error {
	seen := map[string]string{}
	seenIPv6 := map[string]string{}
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

func (s *Store) groupViewsLocked(domains []Domain) []GroupView {
	clientIDs := make([]string, 0, len(s.state.Clients))
	clientsByDomain := map[string][]string{}
	for id, client := range s.state.Clients {
		clientIDs = append(clientIDs, id)
		clientsByDomain[client.DomainID] = append(clientsByDomain[client.DomainID], id)
	}
	sort.Strings(clientIDs)
	allGroupIDs := make([]string, 0, len(domains)+len(s.state.Groups))
	for _, domain := range domains {
		allGroupIDs = append(allGroupIDs, domainGroupID(domain.ID))
	}
	for id, group := range s.state.Groups {
		if group.Type == "custom" {
			allGroupIDs = append(allGroupIDs, id)
		}
	}
	sort.Strings(allGroupIDs)
	views := []GroupView{{ID: AllGroupID, Name: "All", Type: "system", ClientIDs: clientIDs, GroupIDs: allGroupIDs, BuiltIn: true}}
	for _, domain := range domains {
		members := append([]string(nil), clientsByDomain[domain.ID]...)
		sort.Strings(members)
		views = append(views, GroupView{ID: domainGroupID(domain.ID), Name: domain.Name, Type: "domain", ClientIDs: members, BuiltIn: true})
	}
	custom := make([]Group, 0, len(s.state.Groups))
	for _, group := range s.state.Groups {
		if group.Type == "custom" {
			custom = append(custom, group)
		}
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].Name < custom[j].Name })
	for _, group := range custom {
		views = append(views, groupView(group, false))
	}
	return views
}

func groupView(group Group, builtIn bool) GroupView {
	return GroupView{ID: group.ID, Name: group.Name, Type: group.Type, ClientIDs: append([]string(nil), group.ClientIDs...), GroupIDs: append([]string(nil), group.GroupIDs...), BuiltIn: builtIn, CreatedAt: group.CreatedAt, UpdatedAt: group.UpdatedAt}
}

func (s *Store) clientGroupIDsLocked(clientIDValue, domainID string) []string {
	groups := map[string]struct{}{AllGroupID: {}}
	if domainID != "" {
		groups[domainGroupID(domainID)] = struct{}{}
	}
	changed := true
	for changed {
		changed = false
		for _, group := range s.state.Groups {
			if _, ok := groups[group.ID]; ok {
				continue
			}
			if containsID(group.ClientIDs, clientIDValue) || intersectsIDs(group.GroupIDs, groups) {
				groups[group.ID] = struct{}{}
				changed = true
			}
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Store) groupHasChildLocked(groupID, targetID string, seen map[string]bool) bool {
	if seen[groupID] {
		return false
	}
	seen[groupID] = true
	group, ok := s.state.Groups[groupID]
	if !ok {
		return false
	}
	for _, childID := range group.GroupIDs {
		if childID == targetID {
			return true
		}
		if isCustomGroupID(childID) && s.groupHasChildLocked(childID, targetID, seen) {
			return true
		}
	}
	return false
}

func (s *Store) groupIDExistsLocked(id string, allowAll bool) bool {
	if id == AllGroupID {
		return allowAll
	}
	if isDomainGroupID(id) {
		return strings.TrimPrefix(id, "domain:") != ""
	}
	if isCustomGroupID(id) {
		group, ok := s.state.Groups[id]
		return ok && group.Type == "custom"
	}
	return false
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
	next := ids[:0]
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

func domainGroupID(domainID string) string {
	return "domain:" + domainID
}

func customGroupID(id string) string {
	if strings.HasPrefix(id, "custom:") {
		return id
	}
	return "custom:" + id
}

func isCustomGroupID(id string) bool {
	return strings.HasPrefix(id, "custom:")
}

func isDomainGroupID(id string) bool {
	return strings.HasPrefix(id, "domain:")
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

func clientAddressLine(client Client) string {
	addresses := []string{client.IP + "/32"}
	if client.IPv6 != "" {
		addresses = append(addresses, client.IPv6+"/128")
	}
	return strings.Join(addresses, ", ")
}

func clientAllowedIPs(client Client) string {
	addresses := []string{client.IP + "/32"}
	if client.IPv6 != "" {
		addresses = append(addresses, client.IPv6+"/128")
	}
	return strings.Join(addresses, ",")
}
