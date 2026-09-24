package bruecke

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testVPNEvent(id, clientID, decision, outcome string, occurred time.Time) VPNEventUpload {
	desired := "on"
	before := "off"
	after := "on"
	if decision == "local" {
		desired = "off"
		before = "on"
		after = "off"
	}
	return VPNEventUpload{
		EventID: id, OccurredAt: occurred, ClientID: clientID, ComputerName: "PC1",
		Decision: decision, DesiredState: desired, StateBefore: before, StateAfter: after, Outcome: outcome,
		Reason: "fixture",
		Evaluations: []VPNEventEvaluation{{
			ProfileIndex: 1, ProfileType: "wifi", AdapterAlias: "WLAN", AdapterIndex: 16,
			Matched:  decision == "local",
			Expected: VPNEventNetworkValues{Kind: "wifi", SSIDs: []string{"STL-INTERN"}, AddressCIDRs: []string{"10.30.0.0/21"}},
			Actual:   VPNEventNetworkValues{Kind: "wifi", SSIDs: []string{"STL-INTERN"}, AddressCIDRs: []string{"10.30.2.65/21"}},
		}},
	}
}

func TestVPNEventStoreDeduplicatesFiltersPaginatesAndExpires(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	store := NewVPNEventStore(filepath.Join(t.TempDir(), "vpn-events"))
	old := testVPNEvent("old", "client-a", "non_local", "activated", now.Add(-8*24*time.Hour))
	if accepted, err := store.Append([]VPNEventUpload{old}, now.Add(-8*24*time.Hour)); err != nil || accepted != 1 {
		t.Fatalf("append old accepted=%d err=%v", accepted, err)
	}
	incoming := []VPNEventUpload{
		testVPNEvent("event-a", "client-a", "local", "deactivated", now),
		testVPNEvent("event-b", "client-a", "non_local", "activated", now),
		testVPNEvent("event-c", "client-a", "indeterminate", "no_op", now),
	}
	if accepted, err := store.Append(incoming, now); err != nil || accepted != 3 {
		t.Fatalf("append accepted=%d err=%v", accepted, err)
	}
	if accepted, err := store.Append(incoming[:1], now); err != nil || accepted != 0 {
		t.Fatalf("duplicate accepted=%d err=%v", accepted, err)
	}

	first, cursor, err := store.Events(VPNEventQuery{ClientID: "client-a", Limit: 2}, now)
	if err != nil || len(first) != 2 || cursor == "" {
		t.Fatalf("first page events=%d cursor=%q err=%v", len(first), cursor, err)
	}
	second, next, err := store.Events(VPNEventQuery{ClientID: "client-a", Limit: 2, Cursor: cursor}, now)
	if err != nil || len(second) != 1 || next != "" || second[0].EventID == "old" {
		t.Fatalf("second page=%+v cursor=%q err=%v", second, next, err)
	}
	filtered, _, err := store.Events(VPNEventQuery{Decision: "local", Outcome: "deactivated"}, now)
	if err != nil || len(filtered) != 1 || filtered[0].EventID != "event-a" {
		t.Fatalf("filtered=%+v err=%v", filtered, err)
	}
}

func TestVPNEventUploadAuthAndAdminRead(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	dir := t.TempDir()
	app := NewServer(Config{
		BootstrapLogTokenPath: filepath.Join(dir, "upload-token"),
		VPNEventDir:           filepath.Join(dir, "vpn-events"),
	}, ServerDependencies{Clock: ClockFunc(func() time.Time { return now })})
	token, err := app.bootstrapLogToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	payload := VPNEventUploadRequest{Events: []VPNEventUpload{
		testVPNEvent("event-1", "pc1|domain:test", "local", "deactivated", now),
	}}
	payload.Events[0].Reason = strings.Repeat("e", (1<<20)+1)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	request := func(auth bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/vpn-events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		app.Routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := request(false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := request(true); rec.Code != http.StatusOK {
		t.Fatalf("upload status=%d body=%s", rec.Code, rec.Body.String())
	}

	app.sess["admin"] = adminSession{ExpiresAt: now.Add(time.Hour)}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/vpn-events?client_id=pc1%7Cdomain%3Atest&decision=local&outcome=deactivated", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "admin"})
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin read status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response vpnEventListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Events) != 1 || len(response.Events[0].Evaluations) != 1 {
		t.Fatalf("events=%+v", response.Events)
	}
	evaluation := response.Events[0].Evaluations[0]
	if evaluation.Expected.AddressCIDRs[0] != "10.30.0.0/21" || evaluation.Actual.AddressCIDRs[0] != "10.30.2.65/21" {
		t.Fatalf("evaluation=%+v", evaluation)
	}
}
