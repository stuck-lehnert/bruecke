package bruecke

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vpnEventRetention          = 7 * 24 * time.Hour
	vpnEventMaxBatch           = 100
	vpnEventMaxPerClient       = 5000
	vpnEventDefaultLimit       = 200
	vpnEventMaxLimit           = 500
	vpnEventMaxReasonBytes     = 4096
	vpnEventMaxEvaluationCount = 100
	vpnEventUploadMaxBytes     = 16 << 20
)

var ErrVPNEventCursor = errors.New("invalid VPN event cursor")

type VPNEventNetworkValues struct {
	Kind         string   `json:"kind,omitempty"`
	SSIDs        []string `json:"ssids,omitempty"`
	Gateways     []string `json:"gateways,omitempty"`
	AddressCIDRs []string `json:"address_cidrs,omitempty"`
	DNSSuffixes  []string `json:"dns_suffixes,omitempty"`
}

type VPNEventEvaluation struct {
	ProfileIndex int                   `json:"profile_index"`
	ProfileType  string                `json:"profile_type,omitempty"`
	AdapterAlias string                `json:"adapter_alias,omitempty"`
	AdapterIndex int                   `json:"adapter_index,omitempty"`
	Matched      bool                  `json:"matched"`
	UsedFallback bool                  `json:"used_fallback,omitempty"`
	Expected     VPNEventNetworkValues `json:"expected"`
	Actual       VPNEventNetworkValues `json:"actual"`
	Mismatches   []string              `json:"mismatches,omitempty"`
	Unavailable  []string              `json:"unavailable,omitempty"`
}

type VPNEventUpload struct {
	EventID         string               `json:"event_id"`
	OccurredAt      time.Time            `json:"occurred_at"`
	ClientID        string               `json:"client_id"`
	ComputerName    string               `json:"computer_name,omitempty"`
	Hostname        string               `json:"hostname,omitempty"`
	TunnelName      string               `json:"tunnel_name,omitempty"`
	ActuatorVersion string               `json:"actuator_version,omitempty"`
	TriggerSource   string               `json:"trigger_source,omitempty"`
	Decision        string               `json:"decision"`
	DesiredState    string               `json:"desired_state"`
	StateBefore     string               `json:"state_before"`
	StateAfter      string               `json:"state_after"`
	Outcome         string               `json:"outcome"`
	Reason          string               `json:"reason,omitempty"`
	Evaluations     []VPNEventEvaluation `json:"evaluations,omitempty"`
}

type VPNEventUploadRequest struct {
	Events []VPNEventUpload `json:"events"`
}

type VPNEvent struct {
	VPNEventUpload
	ReceivedAt time.Time `json:"received_at"`
}

type VPNEventQuery struct {
	ClientID string
	Decision string
	Outcome  string
	Cursor   string
	Limit    int
}

type vpnEventFile struct {
	ClientID string     `json:"client_id"`
	Events   []VPNEvent `json:"events"`
}

type vpnEventUploadResponse struct {
	Accepted int `json:"accepted"`
}

type vpnEventListResponse struct {
	Events     []VPNEvent `json:"events"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type VPNEventStore struct {
	mu  sync.Mutex
	dir string
}

func NewVPNEventStore(dir string) *VPNEventStore {
	return &VPNEventStore{dir: strings.TrimSpace(dir)}
}

func vpnEventRepository(cfg Config, provided VPNEventRepository) VPNEventRepository {
	if provided != nil {
		return provided
	}
	if strings.TrimSpace(cfg.VPNEventDir) == "" {
		return nil
	}
	return NewVPNEventStore(cfg.VPNEventDir)
}

func (s *VPNEventStore) Append(events []VPNEventUpload, now time.Time) (int, error) {
	if s == nil || s.dir == "" {
		return 0, fmt.Errorf("VPN event store is not configured")
	}
	if len(events) == 0 || len(events) > vpnEventMaxBatch {
		return 0, fmt.Errorf("events must contain between 1 and %d entries", vpnEventMaxBatch)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	normalized := make([]VPNEventUpload, 0, len(events))
	for _, event := range events {
		value, err := normalizeVPNEventUpload(event, now)
		if err != nil {
			return 0, err
		}
		normalized = append(normalized, value)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return 0, fmt.Errorf("create VPN event dir: %w", err)
	}
	grouped := map[string][]VPNEventUpload{}
	for _, event := range normalized {
		grouped[event.ClientID] = append(grouped[event.ClientID], event)
	}
	accepted := 0
	for clientID, incoming := range grouped {
		file, err := s.readClientFile(clientID)
		if err != nil {
			return 0, err
		}
		cutoff := now.Add(-vpnEventRetention)
		kept := file.Events[:0]
		existing := map[string]bool{}
		for _, event := range file.Events {
			if event.ReceivedAt.Before(cutoff) {
				continue
			}
			kept = append(kept, event)
			existing[event.EventID] = true
		}
		file.Events = kept
		for _, event := range incoming {
			if existing[event.EventID] {
				continue
			}
			file.Events = append(file.Events, VPNEvent{VPNEventUpload: event, ReceivedAt: now})
			existing[event.EventID] = true
			accepted++
		}
		sortVPNEventsNewestFirst(file.Events)
		if len(file.Events) > vpnEventMaxPerClient {
			file.Events = file.Events[:vpnEventMaxPerClient]
		}
		file.ClientID = clientID
		if err := s.writeClientFile(clientID, file); err != nil {
			return 0, err
		}
	}
	return accepted, nil
}

func (s *VPNEventStore) Events(query VPNEventQuery, now time.Time) ([]VPNEvent, string, error) {
	if s == nil || s.dir == "" {
		return nil, "", fmt.Errorf("VPN event store is not configured")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	limit := query.Limit
	if limit <= 0 {
		limit = vpnEventDefaultLimit
	}
	if limit > vpnEventMaxLimit {
		limit = vpnEventMaxLimit
	}
	cursorTime, cursorID, err := decodeVPNEventCursor(query.Cursor)
	if err != nil {
		return nil, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []VPNEvent{}, "", nil
		}
		return nil, "", fmt.Errorf("read VPN event dir: %w", err)
	}
	cutoff := now.Add(-vpnEventRetention)
	all := []VPNEvent{}
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if readErr != nil {
			continue
		}
		var file vpnEventFile
		if json.Unmarshal(data, &file) != nil {
			continue
		}
		if query.ClientID != "" && file.ClientID != query.ClientID {
			continue
		}
		for _, event := range file.Events {
			if event.ReceivedAt.Before(cutoff) || (query.Decision != "" && event.Decision != query.Decision) || (query.Outcome != "" && event.Outcome != query.Outcome) {
				continue
			}
			if !cursorTime.IsZero() && !vpnEventOlderThan(event, cursorTime, cursorID) {
				continue
			}
			all = append(all, event)
		}
	}
	sortVPNEventsNewestFirst(all)
	next := ""
	if len(all) > limit {
		all = all[:limit]
		last := all[len(all)-1]
		next = encodeVPNEventCursor(last.ReceivedAt, last.EventID)
	}
	return all, next, nil
}

func (s *VPNEventStore) readClientFile(clientID string) (vpnEventFile, error) {
	path := s.clientPath(clientID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return vpnEventFile{ClientID: clientID}, nil
		}
		return vpnEventFile{}, fmt.Errorf("read VPN events: %w", err)
	}
	var file vpnEventFile
	if err := json.Unmarshal(data, &file); err != nil {
		return vpnEventFile{}, fmt.Errorf("decode VPN events: %w", err)
	}
	return file, nil
}

func (s *VPNEventStore) writeClientFile(clientID string, file vpnEventFile) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode VPN events: %w", err)
	}
	data = append(data, '\n')
	path := s.clientPath(clientID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write VPN events: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace VPN events: %w", err)
	}
	return nil
}

func (s *VPNEventStore) clientPath(clientID string) string {
	hash := sha256.Sum256([]byte(clientID))
	return filepath.Join(s.dir, hex.EncodeToString(hash[:])+".json")
}

func normalizeVPNEventUpload(event VPNEventUpload, now time.Time) (VPNEventUpload, error) {
	event.EventID = strings.TrimSpace(event.EventID)
	event.ClientID = limitBootstrapLogString(event.ClientID, 253)
	if !validBootstrapLogRunID(event.EventID) || event.ClientID == "" {
		return VPNEventUpload{}, fmt.Errorf("event_id and client_id are required")
	}
	event.Decision = strings.ToLower(strings.TrimSpace(event.Decision))
	event.DesiredState = strings.ToLower(strings.TrimSpace(event.DesiredState))
	event.StateBefore = strings.ToLower(strings.TrimSpace(event.StateBefore))
	event.StateAfter = strings.ToLower(strings.TrimSpace(event.StateAfter))
	event.Outcome = strings.ToLower(strings.TrimSpace(event.Outcome))
	if !oneOf(event.Decision, "local", "non_local", "indeterminate") || !oneOf(event.DesiredState, "on", "off") || !oneOf(event.StateBefore, "on", "off", "partial", "unknown") || !oneOf(event.StateAfter, "on", "off", "partial", "unknown") || !oneOf(event.Outcome, "no_op", "activated", "deactivated", "failed") {
		return VPNEventUpload{}, fmt.Errorf("invalid VPN event decision, state, or outcome")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	event.ComputerName = limitBootstrapLogString(event.ComputerName, 160)
	event.Hostname = limitBootstrapLogString(event.Hostname, 253)
	event.TunnelName = limitBootstrapLogString(event.TunnelName, 128)
	event.ActuatorVersion = limitBootstrapLogString(event.ActuatorVersion, 128)
	event.TriggerSource = limitBootstrapLogString(event.TriggerSource, 80)
	event.Reason = limitBootstrapLogString(event.Reason, vpnEventMaxReasonBytes)
	if len(event.Evaluations) > vpnEventMaxEvaluationCount {
		event.Evaluations = event.Evaluations[:vpnEventMaxEvaluationCount]
	}
	for index := range event.Evaluations {
		normalizeVPNEventEvaluation(&event.Evaluations[index])
	}
	return event, nil
}

func normalizeVPNEventEvaluation(value *VPNEventEvaluation) {
	value.ProfileType = limitBootstrapLogString(value.ProfileType, 32)
	value.AdapterAlias = limitBootstrapLogString(value.AdapterAlias, 160)
	value.Mismatches = limitVPNEventStrings(value.Mismatches, 32, 512)
	value.Unavailable = limitVPNEventStrings(value.Unavailable, 32, 512)
	normalizeVPNEventNetworkValues(&value.Expected)
	normalizeVPNEventNetworkValues(&value.Actual)
}

func normalizeVPNEventNetworkValues(value *VPNEventNetworkValues) {
	value.Kind = limitBootstrapLogString(value.Kind, 32)
	value.SSIDs = limitVPNEventStrings(value.SSIDs, 16, 160)
	value.Gateways = limitVPNEventStrings(value.Gateways, 16, 64)
	value.AddressCIDRs = limitVPNEventStrings(value.AddressCIDRs, 32, 64)
	value.DNSSuffixes = limitVPNEventStrings(value.DNSSuffixes, 16, 253)
}

func limitVPNEventStrings(values []string, maxItems, maxBytes int) []string {
	if len(values) > maxItems {
		values = values[:maxItems]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := limitBootstrapLogString(value, maxBytes); normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func sortVPNEventsNewestFirst(events []VPNEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].ReceivedAt.Equal(events[j].ReceivedAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].ReceivedAt.After(events[j].ReceivedAt)
	})
}

func vpnEventOlderThan(event VPNEvent, cursorTime time.Time, cursorID string) bool {
	return event.ReceivedAt.Before(cursorTime) || (event.ReceivedAt.Equal(cursorTime) && event.EventID < cursorID)
}

func encodeVPNEventCursor(receivedAt time.Time, eventID string) string {
	value := receivedAt.UTC().Format(time.RFC3339Nano) + "\n" + eventID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeVPNEventCursor(value string) (time.Time, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return time.Time{}, "", ErrVPNEventCursor
	}
	parts := strings.SplitN(string(data), "\n", 2)
	if len(parts) != 2 || !validBootstrapLogRunID(parts[1]) {
		return time.Time{}, "", ErrVPNEventCursor
	}
	parsed, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", ErrVPNEventCursor
	}
	return parsed.UTC(), parts[1], nil
}

func (s *Server) handleVPNEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bootstrapLogUploadAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.vevents == nil {
		http.Error(w, "VPN event store is not configured", http.StatusServiceUnavailable)
		return
	}
	var req VPNEventUploadRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, vpnEventUploadMaxBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	accepted, err := s.vevents.Append(req.Events, s.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, vpnEventUploadResponse{Accepted: accepted})
}

func (s *Server) handleAdminVPNEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.vevents == nil {
		writeJSON(w, http.StatusOK, vpnEventListResponse{Events: []VPNEvent{}})
		return
	}
	limit := vpnEventDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	events, cursor, err := s.vevents.Events(VPNEventQuery{
		ClientID: strings.TrimSpace(r.URL.Query().Get("client_id")),
		Decision: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("decision"))),
		Outcome:  strings.ToLower(strings.TrimSpace(r.URL.Query().Get("outcome"))),
		Cursor:   strings.TrimSpace(r.URL.Query().Get("cursor")),
		Limit:    limit,
	}, s.now())
	if err != nil {
		if errors.Is(err, ErrVPNEventCursor) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, vpnEventListResponse{Events: events, NextCursor: cursor})
}
