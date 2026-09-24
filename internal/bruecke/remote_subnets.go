package bruecke

import (
	"crypto/rand"
	"crypto/sha256"
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

var ErrRemoteSubnetNotFound = errors.New("remote subnet not found")

type RemoteSubnetState struct {
	Version int                         `json:"version"`
	Subnets map[string]RemoteSubnetSpec `json:"subnets"`
}

type RemoteSubnetSpec struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	ConfigType     string    `json:"config_type"`
	SourceFilename string    `json:"source_filename,omitempty"`
	Subnets        []string  `json:"subnets"`
	FreeForAll     bool      `json:"free_for_all,omitempty"`
	ClientIDs      []string  `json:"client_ids,omitempty"`
	GroupIDs       []string  `json:"group_ids,omitempty"`
	Enabled        bool      `json:"enabled"`
	APCConfig      string    `json:"apc_config,omitempty"`
	OVPNConfig     string    `json:"ovpn_config"`
	OVPNCreds      string    `json:"ovpn_creds,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type RemoteSubnetView struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	ConfigType     string    `json:"config_type"`
	SourceFilename string    `json:"source_filename,omitempty"`
	Subnets        []string  `json:"subnets"`
	ClientIDs      []string  `json:"client_ids,omitempty"`
	GroupIDs       []string  `json:"group_ids,omitempty"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type RemoteSubnetUpdate struct {
	Name      *string
	Subnets   *[]string
	ClientIDs *[]string
	GroupIDs  *[]string
	Enabled   *bool
}

type RemoteSubnetStore struct {
	mu    sync.Mutex
	path  string
	state RemoteSubnetState
}

func OpenRemoteSubnetStore(path string) (*RemoteSubnetStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create remote subnet store dir: %w", err)
	}
	store := &RemoteSubnetStore{
		path: path,
		state: RemoteSubnetState{
			Version: 1,
			Subnets: map[string]RemoteSubnetSpec{},
		},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read remote subnet store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode remote subnet store: %w", err)
	}
	if store.state.Version == 0 {
		store.state.Version = 1
	}
	if store.state.Subnets == nil {
		store.state.Subnets = map[string]RemoteSubnetSpec{}
	}
	changed := false
	for id, subnet := range store.state.Subnets {
		normalized, err := normalizeRemoteSubnetSpec(subnet)
		if err != nil {
			return nil, fmt.Errorf("remote subnet %s: %w", id, err)
		}
		before, _ := json.Marshal(subnet)
		after, _ := json.Marshal(normalized)
		if string(before) != string(after) {
			changed = true
		}
		store.state.Subnets[id] = normalized
	}
	if changed {
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *RemoteSubnetStore) Subnets() []RemoteSubnetView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return remoteSubnetViewsLocked(s.state.Subnets)
}

func (s *RemoteSubnetStore) Specs() []RemoteSubnetSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	specs := make([]RemoteSubnetSpec, 0, len(s.state.Subnets))
	for _, spec := range s.state.Subnets {
		specs = append(specs, copyRemoteSubnetSpec(spec))
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })
	return specs
}

func (s *RemoteSubnetStore) Add(name, configType, filename, config string, subnets, clientIDs, groupIDs []string, now time.Time) (RemoteSubnetView, error) {
	spec, err := newRemoteSubnetSpec(name, configType, filename, config, subnets, clientIDs, groupIDs, now)
	if err != nil {
		return RemoteSubnetView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if spec.ID == "" {
		return RemoteSubnetView{}, fmt.Errorf("remote subnet ID is empty")
	}
	previous, known := s.state.Subnets[spec.ID]
	s.state.Subnets[spec.ID] = spec
	if err := s.saveLocked(); err != nil {
		if known {
			s.state.Subnets[spec.ID] = previous
		} else {
			delete(s.state.Subnets, spec.ID)
		}
		return RemoteSubnetView{}, err
	}
	return remoteSubnetView(spec), nil
}

func (s *RemoteSubnetStore) Update(id string, patch RemoteSubnetUpdate) (RemoteSubnetView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec, ok := s.state.Subnets[id]
	if !ok {
		return RemoteSubnetView{}, ErrRemoteSubnetNotFound
	}
	previous := spec
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return RemoteSubnetView{}, fmt.Errorf("name is required")
		}
		spec.Name = name
	}
	if patch.Subnets != nil {
		normalizedSubnets, err := normalizeRemoteCIDRs(*patch.Subnets)
		if err != nil {
			return RemoteSubnetView{}, err
		}
		spec.Subnets = normalizedSubnets
	}
	if patch.ClientIDs != nil {
		spec.ClientIDs = normalizeIDs(*patch.ClientIDs)
	}
	if patch.GroupIDs != nil {
		spec.GroupIDs = normalizeIDs(*patch.GroupIDs)
	}
	if patch.Enabled != nil {
		spec.Enabled = *patch.Enabled
	}
	spec.UpdatedAt = time.Now().UTC()
	s.state.Subnets[id] = spec
	if err := s.saveLocked(); err != nil {
		s.state.Subnets[id] = previous
		return RemoteSubnetView{}, err
	}
	return remoteSubnetView(spec), nil
}

func (s *RemoteSubnetStore) RemoveClient(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	previous := map[string]RemoteSubnetSpec{}
	for subnetID, spec := range s.state.Subnets {
		if !containsID(spec.ClientIDs, id) {
			continue
		}
		previous[subnetID] = spec
		spec.ClientIDs = removeID(spec.ClientIDs, id)
		spec.UpdatedAt = time.Now().UTC()
		s.state.Subnets[subnetID] = spec
		changed = true
	}
	if !changed {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		for subnetID, spec := range previous {
			s.state.Subnets[subnetID] = spec
		}
		return err
	}
	return nil
}

func (s *RemoteSubnetStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.state.Subnets[id]
	if !ok {
		return ErrRemoteSubnetNotFound
	}
	delete(s.state.Subnets, id)
	if err := s.saveLocked(); err != nil {
		s.state.Subnets[id] = previous
		return err
	}
	return nil
}

func (s *RemoteSubnetStore) AllowedCIDRs(selectedIDs []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	selected := map[string]struct{}{}
	for _, id := range selectedIDs {
		selected[id] = struct{}{}
	}
	seen := map[string]struct{}{}
	var cidrs []string
	ids := make([]string, 0, len(s.state.Subnets))
	for id := range s.state.Subnets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		spec := s.state.Subnets[id]
		if !spec.Enabled {
			continue
		}
		if !spec.FreeForAll && !containsID(spec.GroupIDs, AllGroupID) {
			if _, ok := selected[id]; !ok {
				continue
			}
		}
		for _, cidr := range spec.Subnets {
			if _, ok := seen[cidr]; ok {
				continue
			}
			seen[cidr] = struct{}{}
			cidrs = append(cidrs, cidr)
		}
	}
	sort.Strings(cidrs)
	return cidrs
}

func (s *RemoteSubnetStore) RestrictedIDs(ids []string) ([]string, error) {
	normalized := normalizeRemoteSubnetIDs(ids)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range normalized {
		spec, ok := s.state.Subnets[id]
		if !ok {
			return nil, ErrRemoteSubnetNotFound
		}
		if spec.FreeForAll || containsID(spec.GroupIDs, AllGroupID) {
			return nil, fmt.Errorf("remote subnet %s is assigned to all", id)
		}
	}
	return normalized, nil
}

func (s *RemoteSubnetStore) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode remote subnet store: %w", err)
	}
	data = append(data, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write remote subnet store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace remote subnet store: %w", err)
	}
	return nil
}

func newRemoteSubnetSpec(name, configType, filename, config string, subnets, clientIDs, groupIDs []string, now time.Time) (RemoteSubnetSpec, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return RemoteSubnetSpec{}, fmt.Errorf("name is required")
	}
	config = strings.TrimSpace(config)
	if config == "" {
		return RemoteSubnetSpec{}, fmt.Errorf("config is required")
	}
	configType = strings.ToLower(strings.TrimSpace(configType))
	if configType == "" {
		configType = configTypeFromFilename(filename)
	}
	if configType != "ovpn" && configType != "apc" {
		return RemoteSubnetSpec{}, fmt.Errorf("config type must be ovpn or apc")
	}
	normalizedSubnets, err := normalizeRemoteCIDRs(subnets)
	if err != nil {
		return RemoteSubnetSpec{}, err
	}
	ovpn := config
	creds := ""
	apc := ""
	if configType == "apc" {
		apc = config
		ovpn, creds, err = convertAPCToOVPN(config, filename)
		if err != nil {
			return RemoteSubnetSpec{}, err
		}
	}
	id, err := remoteSubnetID(config, normalizedSubnets, now)
	if err != nil {
		return RemoteSubnetSpec{}, err
	}
	now = now.UTC()
	return RemoteSubnetSpec{ID: id, Name: name, ConfigType: configType, SourceFilename: strings.TrimSpace(filename), Subnets: normalizedSubnets, ClientIDs: normalizeIDs(clientIDs), GroupIDs: normalizeIDs(groupIDs), Enabled: true, APCConfig: apc, OVPNConfig: ovpn, OVPNCreds: creds, CreatedAt: now, UpdatedAt: now}, nil
}

func normalizeRemoteSubnetSpec(spec RemoteSubnetSpec) (RemoteSubnetSpec, error) {
	if spec.ID == "" {
		return RemoteSubnetSpec{}, fmt.Errorf("ID is empty")
	}
	if spec.Name == "" {
		spec.Name = spec.ID
	}
	configType := strings.ToLower(strings.TrimSpace(spec.ConfigType))
	if configType != "ovpn" && configType != "apc" {
		return RemoteSubnetSpec{}, fmt.Errorf("config type must be ovpn or apc")
	}
	subnets, err := normalizeRemoteCIDRs(spec.Subnets)
	if err != nil {
		return RemoteSubnetSpec{}, err
	}
	spec.ConfigType = configType
	spec.Subnets = subnets
	if spec.FreeForAll {
		spec.GroupIDs = append(spec.GroupIDs, AllGroupID)
		spec.FreeForAll = false
	}
	spec.ClientIDs = normalizeIDs(spec.ClientIDs)
	spec.GroupIDs = normalizeIDs(spec.GroupIDs)
	if configType == "apc" && strings.TrimSpace(spec.APCConfig) != "" {
		ovpn, creds, err := convertAPCToOVPN(spec.APCConfig, spec.SourceFilename)
		if err != nil {
			return RemoteSubnetSpec{}, err
		}
		spec.OVPNConfig = ovpn
		spec.OVPNCreds = creds
	}
	if strings.TrimSpace(spec.OVPNConfig) == "" {
		return RemoteSubnetSpec{}, fmt.Errorf("OVPN config is empty")
	}
	return spec, nil
}

func normalizeRemoteCIDRs(raw []string) ([]string, error) {
	seen := map[string]struct{}{}
	cidrs := make([]string, 0, len(raw))
	for _, item := range raw {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' }) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("remote subnet %q is not a valid CIDR", part)
			}
			part = prefix.Masked().String()
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			cidrs = append(cidrs, part)
		}
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("at least one remote subnet is required")
	}
	return cidrs, nil
}

func remoteSubnetViewsLocked(subnets map[string]RemoteSubnetSpec) []RemoteSubnetView {
	views := make([]RemoteSubnetView, 0, len(subnets))
	for _, subnet := range subnets {
		views = append(views, remoteSubnetView(subnet))
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].Name < views[j].Name
	})
	return views
}

func remoteSubnetView(spec RemoteSubnetSpec) RemoteSubnetView {
	return RemoteSubnetView{ID: spec.ID, Name: spec.Name, ConfigType: spec.ConfigType, SourceFilename: spec.SourceFilename, Subnets: append([]string(nil), spec.Subnets...), ClientIDs: append([]string(nil), spec.ClientIDs...), GroupIDs: append([]string(nil), spec.GroupIDs...), Enabled: spec.Enabled, CreatedAt: spec.CreatedAt, UpdatedAt: spec.UpdatedAt}
}

func copyRemoteSubnetSpec(spec RemoteSubnetSpec) RemoteSubnetSpec {
	spec.Subnets = append([]string(nil), spec.Subnets...)
	return spec
}

func remoteSubnetID(config string, subnets []string, now time.Time) (string, error) {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%x", config, strings.Join(subnets, ","), now.UTC().Format(time.RFC3339Nano), randomBytes)))
	return hex.EncodeToString(sum[:16]), nil
}

func configTypeFromFilename(filename string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	if ext == "apc" || ext == "ovpn" {
		return ext
	}
	return ""
}

type apcConfig struct {
	Protocol                string          `json:"protocol"`
	ServerAddress           []string        `json:"server_address"`
	ServerPort              json.RawMessage `json:"server_port"`
	AuthenticationAlgorithm string          `json:"authentication_algorithm"`
	EncryptionAlgorithm     string          `json:"encryption_algorithm"`
	ServerDN                string          `json:"server_dn"`
	CACert                  string          `json:"ca_cert"`
	Certificate             string          `json:"certificate"`
	Key                     string          `json:"key"`
	Username                string          `json:"username"`
	Password                string          `json:"password"`
}

func convertAPCToOVPN(raw, filename string) (string, string, error) {
	var cfg apcConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", "", fmt.Errorf("decode APC config: %w", err)
	}
	if len(cfg.ServerAddress) == 0 || strings.TrimSpace(cfg.ServerAddress[0]) == "" {
		return "", "", fmt.Errorf("APC server_address is required")
	}
	serverPort := strings.Trim(string(cfg.ServerPort), "\"")
	required := map[string]string{
		"protocol":                 cfg.Protocol,
		"server_port":              serverPort,
		"authentication_algorithm": cfg.AuthenticationAlgorithm,
		"encryption_algorithm":     cfg.EncryptionAlgorithm,
		"ca_cert":                  cfg.CACert,
		"certificate":              cfg.Certificate,
		"key":                      cfg.Key,
		"username":                 cfg.Username,
		"password":                 cfg.Password,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) == "null" {
			return "", "", fmt.Errorf("APC %s is required", field)
		}
	}
	credsFile := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	if credsFile == "" || credsFile == "." {
		credsFile = "remote"
	}
	credsFile = sanitizeFilename(credsFile) + "-creds.txt"
	serverCN := serverCNFromDN(cfg.ServerDN)
	remote := fmt.Sprintf("%s %s", strings.TrimSpace(cfg.ServerAddress[0]), serverPort)
	var builder strings.Builder
	fmt.Fprintf(&builder, "client\n")
	fmt.Fprintf(&builder, "dev tun\n")
	fmt.Fprintf(&builder, "proto %s\n", strings.TrimSpace(cfg.Protocol))
	fmt.Fprintf(&builder, "remote %s\n", remote)
	fmt.Fprintf(&builder, "auth %s\n", strings.TrimSpace(cfg.AuthenticationAlgorithm))
	cipher := strings.TrimSpace(cfg.EncryptionAlgorithm)
	fmt.Fprintf(&builder, "cipher %s\n", cipher)
	fmt.Fprintf(&builder, "data-ciphers %s\n", openVPNDataCiphers(cipher))
	fmt.Fprintf(&builder, "data-ciphers-fallback %s\n", cipher)
	if serverCN != "" {
		fmt.Fprintf(&builder, "verify-x509-name %s name\n\n", serverCN)
	} else {
		fmt.Fprintf(&builder, "remote-cert-tls server\n\n")
	}
	fmt.Fprintf(&builder, "<ca>\n%s\n</ca>\n\n", strings.TrimSpace(cfg.CACert))
	fmt.Fprintf(&builder, "<cert>\n%s\n</cert>\n\n", strings.TrimSpace(cfg.Certificate))
	fmt.Fprintf(&builder, "<key>\n%s\n</key>\n\n", strings.TrimSpace(cfg.Key))
	fmt.Fprintf(&builder, "<connection>\nremote %s\n</connection>\n\n", remote)
	fmt.Fprintf(&builder, "auth-user-pass %s\n\n", credsFile)
	fmt.Fprintf(&builder, "auth-nocache\n")
	fmt.Fprintf(&builder, "resolv-retry infinite\n")
	fmt.Fprintf(&builder, "auth-retry nointeract\n")
	fmt.Fprintf(&builder, "keepalive 10 60\n")
	fmt.Fprintf(&builder, "pull-filter ignore \"redirect-gateway\"\n")
	fmt.Fprintf(&builder, "persist-key\n")
	fmt.Fprintf(&builder, "persist-tun\n")
	fmt.Fprintf(&builder, "inactive 0\n")
	return builder.String(), fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cfg.Username), strings.TrimSpace(cfg.Password)), nil
}

func openVPNDataCiphers(cipher string) string {
	defaults := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	for _, item := range defaults {
		if strings.EqualFold(item, cipher) {
			return strings.Join(defaults, ":")
		}
	}
	return strings.Join(append(defaults, cipher), ":")
}

func serverCNFromDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

func sanitizeFilename(raw string) string {
	var builder strings.Builder
	for _, r := range raw {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "remote"
	}
	return builder.String()
}
