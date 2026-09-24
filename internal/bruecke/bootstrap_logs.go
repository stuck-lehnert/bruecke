package bruecke

import (
	"crypto/subtle"
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
	bootstrapLogDefaultRunLimit = 100
	bootstrapLogMaxRunLimit     = 500
	bootstrapLogMaxBatchEvents  = 100
	bootstrapLogMaxEventsPerRun = 2000
	bootstrapLogMaxMessageBytes = 4096
)

var ErrBootstrapLogRunNotFound = errors.New("bootstrap log run not found")

type BootstrapLogUploadRequest struct {
	RunID                 string                    `json:"run_id"`
	ComputerName          string                    `json:"computer_name,omitempty"`
	Hostname              string                    `json:"hostname,omitempty"`
	ClientID              string                    `json:"client_id,omitempty"`
	CertificateSubject    string                    `json:"certificate_subject,omitempty"`
	CertificateIssuer     string                    `json:"certificate_issuer,omitempty"`
	CertificateThumbprint string                    `json:"certificate_thumbprint,omitempty"`
	ServiceBaseURL        string                    `json:"service_base_url,omitempty"`
	TunnelName            string                    `json:"tunnel_name,omitempty"`
	PowerShellVersion     string                    `json:"powershell_version,omitempty"`
	Status                string                    `json:"status,omitempty"`
	Events                []BootstrapLogUploadEvent `json:"events,omitempty"`
}

type BootstrapLogUploadEvent struct {
	Seq     int64     `json:"seq,omitempty"`
	Time    time.Time `json:"time,omitempty"`
	Level   string    `json:"level,omitempty"`
	Phase   string    `json:"phase,omitempty"`
	Message string    `json:"message"`
}

type BootstrapLogRun struct {
	RunID                 string    `json:"run_id"`
	ComputerName          string    `json:"computer_name,omitempty"`
	Hostname              string    `json:"hostname,omitempty"`
	ClientID              string    `json:"client_id,omitempty"`
	CertificateSubject    string    `json:"certificate_subject,omitempty"`
	CertificateIssuer     string    `json:"certificate_issuer,omitempty"`
	CertificateThumbprint string    `json:"certificate_thumbprint,omitempty"`
	ServiceBaseURL        string    `json:"service_base_url,omitempty"`
	TunnelName            string    `json:"tunnel_name,omitempty"`
	PowerShellVersion     string    `json:"powershell_version,omitempty"`
	Status                string    `json:"status,omitempty"`
	LastLevel             string    `json:"last_level,omitempty"`
	LastMessage           string    `json:"last_message,omitempty"`
	FirstSeen             time.Time `json:"first_seen"`
	LastSeen              time.Time `json:"last_seen"`
	LastSeq               int64     `json:"last_seq"`
	EventCount            int       `json:"event_count"`
}

type BootstrapLogEvent struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level,omitempty"`
	Phase   string    `json:"phase,omitempty"`
	Message string    `json:"message"`
}

type bootstrapLogRunFile struct {
	Run    BootstrapLogRun     `json:"run"`
	Events []BootstrapLogEvent `json:"events"`
}

type bootstrapLogRunsResponse struct {
	Runs []BootstrapLogRun `json:"runs"`
}

type bootstrapLogRunResponse struct {
	Run    BootstrapLogRun     `json:"run"`
	Events []BootstrapLogEvent `json:"events"`
}

type bootstrapLogUploadResponse struct {
	OK      bool            `json:"ok"`
	Run     BootstrapLogRun `json:"run"`
	NextSeq int64           `json:"next_seq"`
}

type BootstrapLogStore struct {
	mu  sync.Mutex
	dir string
}

func NewBootstrapLogStore(dir string) *BootstrapLogStore {
	return &BootstrapLogStore{dir: strings.TrimSpace(dir)}
}

func bootstrapLogRepository(cfg Config, provided BootstrapLogRepository) BootstrapLogRepository {
	if provided != nil {
		return provided
	}
	if strings.TrimSpace(cfg.BootstrapLogDir) == "" {
		return nil
	}
	return NewBootstrapLogStore(cfg.BootstrapLogDir)
}

func (s *BootstrapLogStore) Append(req BootstrapLogUploadRequest, now time.Time) (BootstrapLogRun, error) {
	if s == nil || s.dir == "" {
		return BootstrapLogRun{}, fmt.Errorf("bootstrap log store is not configured")
	}
	runID := strings.TrimSpace(req.RunID)
	if !validBootstrapLogRunID(runID) {
		return BootstrapLogRun{}, fmt.Errorf("run_id is required")
	}
	if len(req.Events) > bootstrapLogMaxBatchEvents {
		return BootstrapLogRun{}, fmt.Errorf("too many log events")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return BootstrapLogRun{}, fmt.Errorf("create bootstrap log dir: %w", err)
	}

	path := s.runPath(runID)
	file := bootstrapLogRunFile{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &file); err != nil {
			return BootstrapLogRun{}, fmt.Errorf("decode bootstrap log run: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return BootstrapLogRun{}, fmt.Errorf("read bootstrap log run: %w", err)
	}
	if file.Run.RunID == "" {
		file.Run.RunID = runID
		file.Run.FirstSeen = now
	}
	file.Run.LastSeen = now
	applyBootstrapLogMetadata(&file.Run, req)

	existingSeqs := map[int64]bool{}
	for _, event := range file.Events {
		existingSeqs[event.Seq] = true
		if event.Seq > file.Run.LastSeq {
			file.Run.LastSeq = event.Seq
		}
	}
	for _, incoming := range req.Events {
		seq := incoming.Seq
		if seq <= 0 {
			seq = file.Run.LastSeq + 1
		}
		if existingSeqs[seq] {
			continue
		}
		eventTime := incoming.Time
		if eventTime.IsZero() {
			eventTime = now
		} else {
			eventTime = eventTime.UTC()
		}
		event := BootstrapLogEvent{
			Seq:     seq,
			Time:    eventTime,
			Level:   limitBootstrapLogString(incoming.Level, 32),
			Phase:   limitBootstrapLogString(incoming.Phase, 80),
			Message: limitBootstrapLogString(incoming.Message, bootstrapLogMaxMessageBytes),
		}
		file.Events = append(file.Events, event)
		existingSeqs[seq] = true
		if seq > file.Run.LastSeq {
			file.Run.LastSeq = seq
		}
		file.Run.LastLevel = event.Level
		file.Run.LastMessage = event.Message
	}
	if len(file.Events) > bootstrapLogMaxEventsPerRun {
		file.Events = append([]BootstrapLogEvent(nil), file.Events[len(file.Events)-bootstrapLogMaxEventsPerRun:]...)
	}
	file.Run.EventCount = len(file.Events)
	if file.Run.Status == "" && file.Run.LastLevel != "" {
		file.Run.Status = strings.ToLower(file.Run.LastLevel)
	}
	if err := writeBootstrapLogRunFile(path, file); err != nil {
		return BootstrapLogRun{}, err
	}
	return file.Run, nil
}

func (s *BootstrapLogStore) Runs(limit int) ([]BootstrapLogRun, error) {
	if s == nil || s.dir == "" {
		return nil, fmt.Errorf("bootstrap log store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = bootstrapLogDefaultRunLimit
	}
	if limit > bootstrapLogMaxRunLimit {
		limit = bootstrapLogMaxRunLimit
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read bootstrap log dir: %w", err)
	}
	runs := []BootstrapLogRun{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil || len(data) == 0 {
			continue
		}
		var file bootstrapLogRunFile
		if err := json.Unmarshal(data, &file); err != nil || file.Run.RunID == "" {
			continue
		}
		runs = append(runs, file.Run)
	}
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].LastSeen.After(runs[j].LastSeen)
	})
	if len(runs) > limit {
		runs = runs[:limit]
	}
	return runs, nil
}

func (s *BootstrapLogStore) Run(id string, sinceSeq int64) (BootstrapLogRun, []BootstrapLogEvent, error) {
	if s == nil || s.dir == "" {
		return BootstrapLogRun{}, nil, fmt.Errorf("bootstrap log store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	if !validBootstrapLogRunID(id) {
		return BootstrapLogRun{}, nil, ErrBootstrapLogRunNotFound
	}
	data, err := os.ReadFile(s.runPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return BootstrapLogRun{}, nil, ErrBootstrapLogRunNotFound
		}
		return BootstrapLogRun{}, nil, fmt.Errorf("read bootstrap log run: %w", err)
	}
	var file bootstrapLogRunFile
	if err := json.Unmarshal(data, &file); err != nil {
		return BootstrapLogRun{}, nil, fmt.Errorf("decode bootstrap log run: %w", err)
	}
	events := file.Events
	if sinceSeq > 0 {
		filtered := make([]BootstrapLogEvent, 0, len(events))
		for _, event := range events {
			if event.Seq > sinceSeq {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}
	return file.Run, events, nil
}

func (s *BootstrapLogStore) runPath(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func writeBootstrapLogRunFile(path string, file bootstrapLogRunFile) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap log run: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write bootstrap log run: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace bootstrap log run: %w", err)
	}
	return nil
}

func applyBootstrapLogMetadata(run *BootstrapLogRun, req BootstrapLogUploadRequest) {
	if value := limitBootstrapLogString(req.ComputerName, 160); value != "" {
		run.ComputerName = value
	}
	if value := limitBootstrapLogString(req.Hostname, 253); value != "" {
		run.Hostname = value
	}
	if value := limitBootstrapLogString(req.ClientID, 253); value != "" {
		run.ClientID = value
	}
	if value := limitBootstrapLogString(req.CertificateSubject, 512); value != "" {
		run.CertificateSubject = value
	}
	if value := limitBootstrapLogString(req.CertificateIssuer, 512); value != "" {
		run.CertificateIssuer = value
	}
	if value := limitBootstrapLogString(req.CertificateThumbprint, 128); value != "" {
		run.CertificateThumbprint = value
	}
	if value := limitBootstrapLogString(req.ServiceBaseURL, 512); value != "" {
		run.ServiceBaseURL = value
	}
	if value := limitBootstrapLogString(req.TunnelName, 128); value != "" {
		run.TunnelName = value
	}
	if value := limitBootstrapLogString(req.PowerShellVersion, 128); value != "" {
		run.PowerShellVersion = value
	}
	if value := limitBootstrapLogString(req.Status, 80); value != "" {
		run.Status = value
	}
}

func validBootstrapLogRunID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func limitBootstrapLogString(value string, maxBytes int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	last := 0
	for index := range value {
		if index > maxBytes {
			break
		}
		last = index
	}
	if last <= 0 {
		return ""
	}
	return strings.TrimSpace(value[:last])
}

func (s *Server) handleBootstrapLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bootstrapLogUploadAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.blogs == nil {
		http.Error(w, "bootstrap log store is not configured", http.StatusServiceUnavailable)
		return
	}
	var req BootstrapLogUploadRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	run, err := s.blogs.Append(req, s.now())
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("bootstrap log upload failed run=%s: %v", req.RunID, err)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, bootstrapLogUploadResponse{OK: true, Run: run, NextSeq: run.LastSeq + 1})
}

func (s *Server) handleAdminBootstrapLogRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := bootstrapLogDefaultRunLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	if s.blogs == nil {
		writeJSON(w, http.StatusOK, bootstrapLogRunsResponse{})
		return
	}
	runs, err := s.blogs.Runs(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, bootstrapLogRunsResponse{Runs: runs})
}

func (s *Server) handleAdminBootstrapLogRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/bootstrap-logs/runs/")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	sinceSeq := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("since_seq")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid since_seq", http.StatusBadRequest)
			return
		}
		sinceSeq = parsed
	}
	if s.blogs == nil {
		http.NotFound(w, r)
		return
	}
	run, events, err := s.blogs.Run(id, sinceSeq)
	if err != nil {
		if errors.Is(err, ErrBootstrapLogRunNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, bootstrapLogRunResponse{Run: run, Events: events})
}

func (s *Server) bootstrapLogUploadAuthorized(r *http.Request) bool {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return false
	}
	provided := strings.TrimSpace(value[len("Bearer "):])
	if provided == "" {
		return false
	}
	expected, err := s.bootstrapLogToken()
	if err != nil || expected == "" {
		if err != nil && s.logger != nil {
			s.logger.Printf("bootstrap log token unavailable: %v", err)
		}
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *Server) bootstrapLogToken() (string, error) {
	s.bmu.Lock()
	defer s.bmu.Unlock()
	if s.btoken != "" {
		return s.btoken, nil
	}
	path := strings.TrimSpace(s.cfg.BootstrapLogTokenPath)
	if path == "" {
		token, err := randomToken()
		if err != nil {
			return "", err
		}
		s.btoken = token
		return token, nil
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if token := strings.TrimSpace(string(data)); token != "" {
			s.btoken = token
			return token, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read bootstrap log token: %w", err)
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create bootstrap log token dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write bootstrap log token: %w", err)
	}
	s.btoken = token
	return token, nil
}
