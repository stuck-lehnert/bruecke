package bruecke

import (
	"errors"
	"net/http"
)

func (s *Server) handleAdminSSHClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		Hostname  string `json:"hostname"`
		DomainID  string `json:"domain_id"`
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hostname, err := normalizeHostname(req.Hostname)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, publicKey, err := parseSSHPublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain, err := s.domain(req.DomainID)
	if err != nil {
		http.Error(w, "domain not found", http.StatusBadRequest)
		return
	}
	client, err := s.store.Rotate(r.Context(), Enrollment{
		Type:       "ssh",
		Hostname:   hostname,
		DomainID:   domain.ID,
		DomainName: domain.Name,
		PublicKey:  publicKey,
		Settings:   domain.VPNSettings(),
		IssuedAt:   s.now(),
	}, nil)
	if errors.Is(err, ErrClientExists) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("create SSH client: %v", err)
		}
		http.Error(w, "SSH client creation failed", http.StatusInternalServerError)
		return
	}
	if err := s.syncRemoteRuntime(r.Context()); err != nil {
		http.Error(w, "SSH client created, but remote subnet apply failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, s.adminClient(client, nil, s.now()))
}
