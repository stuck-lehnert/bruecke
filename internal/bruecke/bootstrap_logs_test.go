package bruecke

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapLogUploadAuthAndAdminRead(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	dir := t.TempDir()
	app := NewServer(Config{BootstrapLogDir: filepath.Join(dir, "logs"), BootstrapLogTokenPath: filepath.Join(dir, "bootstrap-log-token")}, ServerDependencies{Clock: ClockFunc(func() time.Time { return now })})
	token, err := app.bootstrapLogToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	payload := BootstrapLogUploadRequest{
		RunID:                 "run1",
		ComputerName:          "PC1",
		Hostname:              "pc1.example.com",
		CertificateThumbprint: "ABCDEF",
		Status:                "failed",
		Events: []BootstrapLogUploadEvent{
			{Seq: 1, Time: now, Level: "info", Phase: "bootstrap", Message: "started"},
			{Seq: 2, Time: now.Add(time.Second), Level: "error", Phase: "enrollment", Message: "Zertifikat für Gerät äöü konnte nicht geprüft werden"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/bootstrap-logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/bootstrap-logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status=%d body=%s", rec.Code, rec.Body.String())
	}

	app.sess["admin"] = adminSession{ExpiresAt: now.Add(time.Hour)}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/bootstrap-logs/runs", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "admin"})
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("runs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var runs bootstrapLogRunsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if len(runs.Runs) != 1 || runs.Runs[0].RunID != "run1" || runs.Runs[0].Status != "failed" || runs.Runs[0].LastSeq != 2 {
		t.Fatalf("runs=%+v", runs.Runs)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/bootstrap-logs/runs/run1?since_seq=1", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "admin"})
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", rec.Code, rec.Body.String())
	}
	var detail bootstrapLogRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if len(detail.Events) != 1 || detail.Events[0].Seq != 2 || detail.Events[0].Message != "Zertifikat für Gerät äöü konnte nicht geprüft werden" {
		t.Fatalf("events=%+v", detail.Events)
	}
}

func TestBootstrapLogStoreBoundsAndDeduplicatesEvents(t *testing.T) {
	store := NewBootstrapLogStore(filepath.Join(t.TempDir(), "logs"))
	now := time.Unix(200, 0).UTC()
	first := BootstrapLogUploadRequest{RunID: "run2", Status: "running", Events: []BootstrapLogUploadEvent{{Seq: 1, Message: "one"}, {Seq: 2, Message: "two"}}}
	if _, err := store.Append(first, now); err != nil {
		t.Fatalf("append first: %v", err)
	}
	second := BootstrapLogUploadRequest{RunID: "run2", ClientID: "pc1|domain", Status: "complete", Events: []BootstrapLogUploadEvent{{Seq: 2, Message: "two duplicate"}, {Seq: 3, Message: "three"}}}
	run, err := store.Append(second, now.Add(time.Second))
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if run.ClientID != "pc1|domain" || run.Status != "complete" || run.EventCount != 3 || run.LastSeq != 3 {
		t.Fatalf("run=%+v", run)
	}
	_, events, err := store.Run("run2", 0)
	if err != nil {
		t.Fatalf("run detail: %v", err)
	}
	if len(events) != 3 || events[1].Message != "two" || events[2].Message != "three" {
		t.Fatalf("events=%+v", events)
	}
}
