package bruecke

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, s.adminClientsResponse(r))
}

func (s *Server) adminClientsResponse(r *http.Request) adminClientsResponse {
	clients := s.store.Clients()
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].Hostname < clients[j].Hostname
	})

	statuses := map[string]PeerStatus{}
	var err error
	if s.wg != nil {
		statuses, err = s.wg.PeerStatuses(r.Context())
	}
	statusError := ""
	if err != nil {
		statusError = err.Error()
		if s.logger != nil {
			s.logger.Printf("wireguard status failed: %v", err)
		}
	}

	response := adminClientsResponse{StatusError: statusError}
	for _, client := range clients {
		response.Clients = append(response.Clients, s.adminClient(client, statuses, s.now()))
	}
	return response
}

func (s *Server) handleAdminManualEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req adminManualEnrollRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hostname, err := normalizeHostname(req.Hostname)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain, err := s.domain(req.DomainID)
	if err != nil {
		if errors.Is(err, ErrDomainNotFound) {
			http.Error(w, "domain not found", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	privateKey, publicKey, err := s.keys.GenerateWireGuardKeyPair()
	if err != nil {
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}

	client, config, _, err := s.issueClientConfig(r.Context(), Enrollment{
		Hostname:           hostname,
		DomainID:           domain.ID,
		DomainName:         domain.Name,
		PublicKey:          publicKey,
		CertificateSubject: "manual enrollment",
		IssuedAt:           s.now(),
	}, privateKey)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("manual enroll failed hostname=%s: %v", hostname, err)
		}
		http.Error(w, "manual enrollment failed", http.StatusInternalServerError)
		return
	}

	statuses, err := s.wg.PeerStatuses(r.Context())
	if err != nil && s.logger != nil {
		s.logger.Printf("wireguard status failed: %v", err)
	}
	writeJSON(w, http.StatusOK, adminManualEnrollResponse{
		Hostname: client.Hostname,
		Address:  clientAddressLine(client),
		Config:   config,
		Client:   s.adminClient(client, statuses, s.now()),
	})
}

func (s *Server) handleAdminClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		methodNotAllowed(w, http.MethodPatch+", "+http.MethodDelete)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/admin/clients/")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodDelete {
		client, err := s.store.DeleteClient(r.Context(), id, func(client Client) error {
			if client.Type == "ssh" {
				return nil
			}
			if s.wg == nil {
				return nil
			}
			return s.wg.SetPeer(r.Context(), client.PublicKey, clientAllowedIPs(client), false)
		})
		if err != nil {
			if errors.Is(err, ErrClientNotFound) {
				http.NotFound(w, r)
				return
			}
			if s.logger != nil {
				s.logger.Printf("delete client failed client=%s: %v", id, err)
			}
			http.Error(w, "client delete failed", http.StatusInternalServerError)
			return
		}
		if s.ssh != nil {
			s.ssh.Disconnect(client.ID)
		}
		if s.remote != nil {
			if err := s.remote.RemoveClient(client.ID); err != nil {
				http.Error(w, "remote subnet client cleanup failed", http.StatusInternalServerError)
				return
			}
		}
		if !s.applyRemoteRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req adminUpdateClientRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var client Client
	var err error
	if req.Enabled != nil {
		client, err = s.store.SetClientEnabled(r.Context(), id, *req.Enabled, func(client Client) error {
			if client.Type == "ssh" {
				return nil
			}
			return s.wg.SetPeer(r.Context(), client.PublicKey, clientAllowedIPs(client), !client.Disabled)
		})
	} else {
		client, err = s.store.Client(id)
	}
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			http.NotFound(w, r)
			return
		}
		if s.logger != nil {
			s.logger.Printf("set client enabled failed client=%s: %v", id, err)
		}
		http.Error(w, "client update failed", http.StatusInternalServerError)
		return
	}
	if s.ssh != nil {
		s.ssh.Disconnect(client.ID)
	}
	if req.RemoteSubnetIDs != nil {
		remoteSubnetIDs := req.RemoteSubnetIDs
		if s.remote != nil {
			remoteSubnetIDs, err = s.remote.RestrictedIDs(req.RemoteSubnetIDs)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		client, err = s.store.SetClientRemoteSubnetIDs(id, remoteSubnetIDs)
		if err != nil {
			if errors.Is(err, ErrClientNotFound) {
				http.NotFound(w, r)
				return
			}
			if s.logger != nil {
				s.logger.Printf("set client remote subnets failed client=%s: %v", id, err)
			}
			http.Error(w, "client update failed", http.StatusInternalServerError)
			return
		}
	}
	if !s.applyRemoteRuntime(w, r) {
		return
	}

	statuses, err := s.wg.PeerStatuses(r.Context())
	if err != nil && s.logger != nil {
		s.logger.Printf("wireguard status failed: %v", err)
	}
	writeJSON(w, http.StatusOK, s.adminClient(client, statuses, s.now()))
}

func (s *Server) adminClient(client Client, statuses map[string]PeerStatus, now time.Time) adminClient {
	response := adminClient{
		Type:                "wireguard",
		ID:                  client.ID,
		Hostname:            client.Hostname,
		DomainID:            client.DomainID,
		DomainName:          client.DomainName,
		IP:                  client.IP,
		IPv6:                client.IPv6,
		PublicKey:           client.PublicKey,
		GroupIDs:            append([]string(nil), client.GroupIDs...),
		RemoteSubnetIDs:     append([]string(nil), client.RemoteSubnetIDs...),
		Enabled:             !client.Disabled,
		CertificateSubject:  client.CertificateSubject,
		CertificateSerial:   client.CertificateSerial,
		CertificateNotAfter: client.CertificateNotAfter,
		CreatedAt:           client.CreatedAt,
		UpdatedAt:           client.UpdatedAt,
	}
	if client.Type == "ssh" {
		response.Type = "ssh"
		if key, _, err := parseSSHPublicKey(client.PublicKey); err == nil {
			response.SSHFingerprint = ssh.FingerprintSHA256(key)
		}
		if s.ssh != nil && !client.Disabled {
			response.Connected, response.LatestHandshake = s.ssh.Status(client.ID)
		}
		return response
	}
	status, ok := statuses[client.PublicKey]
	if ok && !status.LatestHandshake.IsZero() {
		latest := status.LatestHandshake
		response.LatestHandshake = &latest
		response.Connected = now.Sub(latest) <= s.cfg.WGConnectedWithin
	}
	return response
}
