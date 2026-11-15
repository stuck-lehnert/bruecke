package bruecke

import (
	"errors"
	"net/http"
	"strings"
)

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
		if !s.applyRemoteRuntime(w, r) {
			return
		}
		writeJSON(w, http.StatusCreated, subnet)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
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
		if !s.applyRemoteRuntime(w, r) {
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
		if !s.applyRemoteRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodPatch+", "+http.MethodDelete)
	}
}

func (s *Server) normalizeAdminAssignments(clientIDs, groupIDs []string) ([]string, []string, error) {
	if s.store == nil {
		return normalizeIDs(clientIDs), normalizeIDs(groupIDs), nil
	}
	return s.store.NormalizeAssignmentReferences(clientIDs, groupIDs)
}
