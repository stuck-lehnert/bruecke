package bruecke

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const adminCookieName = "bruecke_admin"
const adminClientsStreamInterval = 5 * time.Second

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.AdminHash == "" {
		http.Error(w, "admin auth is not configured", http.StatusServiceUnavailable)
		return
	}

	var req adminLoginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !compareBcryptHash(s.cfg.AdminHash, req.Password) {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	token, err := randomToken()
	if err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	expires := s.now().Add(s.cfg.AdminSessionTTL)

	s.smu.Lock()
	s.sess[token] = adminSession{ExpiresAt: expires}
	s.smu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.cfg.AdminSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.AdminCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, adminSessionResponse{Authenticated: true})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(adminCookieName); err == nil {
		s.smu.Lock()
		delete(s.sess, cookie.Value)
		s.smu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.AdminCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, adminSessionResponse{Authenticated: false})
}

func (s *Server) handleAdminSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, adminSessionResponse{Authenticated: s.adminAuthenticated(r)})
}

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.adminClientsResponse(r))
}

func (s *Server) handleAdminClientsWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !webSocketHeaderContains(r.Header, "Connection", "upgrade") || !webSocketHeaderContains(r.Header, "Upgrade", "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "websocket key required", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	acceptHash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(acceptHash[:])
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	send := func() error {
		payload, err := json.Marshal(s.adminClientsResponse(r))
		if err != nil {
			return err
		}
		if err := writeWebSocketText(rw, payload); err != nil {
			return err
		}
		return rw.Flush()
	}
	if err := send(); err != nil {
		return
	}
	ticker := time.NewTicker(adminClientsStreamInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := send(); err != nil {
				return
			}
		}
	}
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
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		w.Header().Set("Allow", http.MethodPatch+", "+http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		if s.remote != nil {
			if err := s.remote.RemoveClient(client.ID); err != nil {
				http.Error(w, "remote subnet client cleanup failed", http.StatusInternalServerError)
				return
			}
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
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
	if err := s.syncRemoteRuntime(r.Context()); err != nil {
		if s.logger != nil {
			s.logger.Printf("remote subnet sync failed: %v", err)
		}
		http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
		return
	}

	statuses, err := s.wg.PeerStatuses(r.Context())
	if err != nil && s.logger != nil {
		s.logger.Printf("wireguard status failed: %v", err)
	}
	writeJSON(w, http.StatusOK, s.adminClient(client, statuses, s.now()))
}

func (s *Server) handleAdminRemoteSubnets(w http.ResponseWriter, r *http.Request) {
	if s.remote == nil {
		http.Error(w, "remote subnet store is not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, adminRemoteSubnetsResponse{Subnets: s.remote.Subnets()})
	case http.MethodPost:
		var req adminRemoteSubnetCreateRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		groupIDs := append([]string(nil), req.GroupIDs...)
		if req.FreeForAll {
			groupIDs = append(groupIDs, AllGroupID)
		}
		clientIDs, groupIDs, err := s.normalizeAdminAssignments(req.ClientIDs, groupIDs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		subnet, err := s.remote.Add(req.Name, req.ConfigType, req.SourceFilename, req.Config, req.Subnets, clientIDs, groupIDs, s.now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, subnet)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminRemoteSubnet(w http.ResponseWriter, r *http.Request) {
	if s.remote == nil {
		http.Error(w, "remote subnet store is not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/remote-subnets/")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req adminRemoteSubnetUpdateRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		clientIDs := req.ClientIDs
		groupIDs := req.GroupIDs
		if req.FreeForAll != nil && groupIDs == nil {
			ids := []string{}
			if *req.FreeForAll {
				ids = append(ids, AllGroupID)
			}
			groupIDs = &ids
		}
		if clientIDs != nil || groupIDs != nil {
			var normalizedClients, normalizedGroups []string
			var normalizeErr error
			if clientIDs != nil {
				normalizedClients = *clientIDs
			}
			if groupIDs != nil {
				normalizedGroups = *groupIDs
			}
			normalizedClients, normalizedGroups, normalizeErr = s.normalizeAdminAssignments(normalizedClients, normalizedGroups)
			if normalizeErr != nil {
				http.Error(w, normalizeErr.Error(), http.StatusBadRequest)
				return
			}
			if clientIDs != nil {
				clientIDs = &normalizedClients
			}
			if groupIDs != nil {
				groupIDs = &normalizedGroups
			}
		}
		subnet, err := s.remote.Update(id, RemoteSubnetUpdate{Name: req.Name, Subnets: req.Subnets, ClientIDs: clientIDs, GroupIDs: groupIDs, Enabled: req.Enabled})
		if err != nil {
			if errors.Is(err, ErrRemoteSubnetNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, subnet)
	case http.MethodDelete:
		if err := s.remote.Delete(id); err != nil {
			if errors.Is(err, ErrRemoteSubnetNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "remote subnet delete failed", http.StatusInternalServerError)
			return
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", http.MethodPatch+", "+http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "client store is not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, adminGroupsResponse{Groups: s.store.Groups(s.domains())})
	case http.MethodPost:
		var req adminCreateGroupRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		group, err := s.store.AddGroup(req.Name, s.now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, group)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminGroup(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "client store is not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/groups/")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req adminUpdateGroupRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		group, err := s.store.UpdateGroup(id, req.Name, req.ClientIDs, req.GroupIDs)
		if err != nil {
			if errors.Is(err, ErrGroupNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, group)
	case http.MethodDelete:
		if err := s.store.DeleteGroup(id); err != nil {
			if errors.Is(err, ErrGroupNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "group delete failed", http.StatusInternalServerError)
			return
		}
		if err := s.syncRemoteRuntime(r.Context()); err != nil {
			if s.logger != nil {
				s.logger.Printf("remote subnet sync failed: %v", err)
			}
			http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", http.MethodPatch+", "+http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminDomains(w http.ResponseWriter, r *http.Request) {
	if s.roots == nil {
		http.Error(w, "domain store is not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, adminDomainsResponse{Domains: s.roots.Domains()})
	case http.MethodPost:
		var req adminCreateDomainRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previous, err := s.currentInterfaceSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		domain, err := s.roots.AddDomain(req.Name, req.PEM, req.DNSServers, req.SearchDomain, req.domainLocalNetworks(), req.AutoEnrollEnabled, s.now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.reconfigureInterface(r.Context(), previous); err != nil {
			if s.logger != nil {
				s.logger.Printf("wireguard domain apply failed: %v", err)
			}
			http.Error(w, "domain apply failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, domain)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminDomain(w http.ResponseWriter, r *http.Request) {
	if s.roots == nil {
		http.Error(w, "domain store is not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/domains/")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req adminUpdateDomainRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previous, err := s.currentInterfaceSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		domain, err := s.roots.UpdateDomain(id, DomainPatch{Name: req.Name, PEM: req.PEM, DNSServers: req.DNSServers, SearchDomain: req.SearchDomain, LocalNetworks: req.domainLocalNetworks(), AutoEnrollEnabled: req.AutoEnrollEnabled})
		if err != nil {
			if errors.Is(err, ErrDomainNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.reconfigureInterface(r.Context(), previous); err != nil {
			if s.logger != nil {
				s.logger.Printf("wireguard domain apply failed: %v", err)
			}
			http.Error(w, "domain apply failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, domain)
	case http.MethodDelete:
		var req adminDeleteDomainRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.cfg.AdminHash == "" {
			http.Error(w, "admin auth is not configured", http.StatusServiceUnavailable)
			return
		}
		if !compareBcryptHash(s.cfg.AdminHash, req.Password) {
			http.Error(w, "invalid password", http.StatusUnauthorized)
			return
		}
		if _, err := s.roots.Domain(id); err != nil {
			if errors.Is(err, ErrDomainNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s.store != nil {
			for _, client := range s.store.Clients() {
				if client.DomainID == id {
					http.Error(w, "domain has enrolled clients; remove them first", http.StatusConflict)
					return
				}
			}
			for _, group := range s.store.Groups(s.domains()) {
				if group.Type == "custom" && containsID(group.GroupIDs, domainGroupID(id)) {
					http.Error(w, "domain is used by a group; remove the assignment first", http.StatusConflict)
					return
				}
			}
		}
		if s.remote != nil {
			for _, subnet := range s.remote.Subnets() {
				if containsID(subnet.GroupIDs, domainGroupID(id)) {
					http.Error(w, "domain is used by a remote subnet; remove the assignment first", http.StatusConflict)
					return
				}
			}
		}
		previous, err := s.currentInterfaceSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		remaining := make([]Domain, 0)
		for _, domain := range s.roots.Domains() {
			if domain.ID != id {
				remaining = append(remaining, domain)
			}
		}
		next, err := domainInterfaceSettings(remaining, s.baseVPNSettings())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var clients []Client
		if s.store != nil {
			clients = s.store.Clients()
		}
		if s.wg != nil {
			if err := s.wg.Reconfigure(r.Context(), previous, next, clients); err != nil {
				http.Error(w, "domain delete apply failed", http.StatusInternalServerError)
				return
			}
		}
		if err := s.roots.Delete(id); err != nil {
			if s.wg != nil {
				if restoreErr := s.wg.Reconfigure(r.Context(), next, previous, clients); restoreErr != nil && s.logger != nil {
					s.logger.Printf("wireguard domain delete rollback failed: %v", restoreErr)
				}
			}
			if errors.Is(err, ErrDomainNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", http.MethodPatch+", "+http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminAuthenticated(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) adminAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	s.smu.Lock()
	defer s.smu.Unlock()

	session, ok := s.sess[cookie.Value]
	if !ok {
		return false
	}
	if !s.now().Before(session.ExpiresAt) {
		delete(s.sess, cookie.Value)
		return false
	}
	return true
}

func (s *Server) adminClient(client Client, statuses map[string]PeerStatus, now time.Time) adminClient {
	response := adminClient{
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
	status, ok := statuses[client.PublicKey]
	if ok && !status.LatestHandshake.IsZero() {
		latest := status.LatestHandshake
		response.LatestHandshake = &latest
		response.Connected = now.Sub(latest) <= s.cfg.WGConnectedWithin
	}
	return response
}

func (s *Server) syncRemoteRuntime(ctx context.Context) error {
	if s.rruntime == nil || s.remote == nil || s.store == nil {
		return nil
	}
	return s.rruntime.Sync(ctx, s.remote.Specs(), s.store.Clients())
}

func (s *Server) domains() []Domain {
	if s.roots == nil {
		return nil
	}
	return s.roots.Domains()
}

func (s *Server) normalizeAdminAssignments(clientIDs, groupIDs []string) ([]string, []string, error) {
	if s.store == nil {
		return normalizeIDs(clientIDs), normalizeIDs(groupIDs), nil
	}
	return s.store.NormalizeAssignmentReferences(clientIDs, groupIDs)
}

func (s *Server) currentInterfaceSettings() (VPNSettings, error) {
	return domainInterfaceSettings(s.domains(), s.baseVPNSettings())
}

func (s *Server) reconfigureInterface(ctx context.Context, previous VPNSettings) error {
	if s.wg == nil {
		return nil
	}
	next, err := s.currentInterfaceSettings()
	if err != nil {
		return err
	}
	return s.wg.Reconfigure(ctx, previous, next, s.store.Clients())
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func webSocketHeaderContains(header http.Header, key, want string) bool {
	for _, value := range header.Values(key) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}

func writeWebSocketText(writer io.Writer, payload []byte) error {
	header := []byte{0x81}
	switch {
	case len(payload) <= 125:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, 0, 0)
		binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[2:], uint64(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func compareBcryptHash(hash, password string) bool {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
		return true
	}
	if strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte("$2a$"+strings.TrimPrefix(hash, "$2y$")), []byte(password)) == nil
	}
	return false
}
