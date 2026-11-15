package bruecke

import (
	"context"
	"net/http"
)

func (s *Server) syncRemoteRuntime(ctx context.Context) error {
	if s.remoteRuntime == nil || s.remote == nil || s.store == nil {
		return nil
	}
	return s.remoteRuntime.Sync(ctx, s.remote.Specs(), s.store.Clients())
}

func (s *Server) applyRemoteRuntime(w http.ResponseWriter, r *http.Request) bool {
	if err := s.syncRemoteRuntime(r.Context()); err != nil {
		if s.logger != nil {
			s.logger.Printf("remote subnet sync failed: %v", err)
		}
		http.Error(w, "remote subnet apply failed", http.StatusInternalServerError)
		return false
	}
	return true
}
