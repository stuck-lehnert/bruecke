package bruecke

import (
	"errors"
	"net/http"
	"strings"
)

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
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
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
		if !s.applyRemoteRuntime(w, r) {
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
		if !s.applyRemoteRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodPatch+", "+http.MethodDelete)
	}
}
