package bruecke

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

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
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
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
		domain, err := s.roots.UpdateDomain(id, DomainPatch{
			Name:              req.Name,
			PEM:               req.PEM,
			DNSServers:        req.DNSServers,
			SearchDomain:      req.SearchDomain,
			LocalNetworks:     req.domainLocalNetworks(),
			AutoEnrollEnabled: req.AutoEnrollEnabled,
		})
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
		methodNotAllowed(w, http.MethodPatch+", "+http.MethodDelete)
	}
}

func (s *Server) domains() []Domain {
	if s.roots == nil {
		return nil
	}
	return s.roots.Domains()
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
