package bruecke

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testWireGuard struct {
	statuses map[string]PeerStatus
}

func (w testWireGuard) Configure(context.Context, VPNSettings) error { return nil }
func (w testWireGuard) Reconfigure(context.Context, VPNSettings, VPNSettings, []Client) error {
	return nil
}
func (w testWireGuard) RotatePeer(context.Context, string, string, string, bool) error { return nil }
func (w testWireGuard) SetPeer(context.Context, string, string, bool) error            { return nil }
func (w testWireGuard) Sync(context.Context, []Client) error                           { return nil }
func (w testWireGuard) PeerStatuses(context.Context) (map[string]PeerStatus, error) {
	return w.statuses, nil
}

func TestAdminClientsWebSocketStreamsStatus(t *testing.T) {
	network, serverIP, ipv6Net, ipv6IP := testPools()
	store, err := OpenStore(t.TempDir()+"/bruecke.json", network, serverIP, ipv6Net, ipv6IP)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	now := time.Unix(100, 0).UTC()
	client, err := store.Rotate(context.Background(), Enrollment{Hostname: "pc1", DomainID: "domain-a", DomainName: "Domain A", Settings: testVPNSettings(), PublicKey: "pub1", IssuedAt: now}, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	app := NewServer(Config{WGConnectedWithin: time.Minute}, ServerDependencies{
		Clients:   store,
		WireGuard: testWireGuard{statuses: map[string]PeerStatus{client.PublicKey: {LatestHandshake: now}}},
		Clock:     ClockFunc(func() time.Time { return now }),
	})
	app.sess["token"] = adminSession{ExpiresAt: now.Add(time.Hour)}

	httpServer := httptest.NewServer(app.Routes())
	defer httpServer.Close()
	addr := strings.TrimPrefix(httpServer.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	_, err = fmt.Fprintf(conn, "GET /api/admin/clients/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCookie: %s=token\r\n\r\n", addr, adminCookieName)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(status, "101 Switching Protocols") {
		t.Fatalf("unexpected status: %s", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload, err := readWebSocketPayload(reader)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	var response adminClientsResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Clients) != 1 || response.Clients[0].Hostname != "pc1" || !response.Clients[0].Connected {
		t.Fatalf("response=%+v", response)
	}
}

func readWebSocketPayload(reader *bufio.Reader) ([]byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if first != 0x81 {
		return nil, fmt.Errorf("unexpected frame type 0x%x", first)
	}
	second, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	length := int(second & 0x7f)
	switch length {
	case 126:
		var bytes [2]byte
		if _, err := io.ReadFull(reader, bytes[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(bytes[:]))
	case 127:
		var bytes [8]byte
		if _, err := io.ReadFull(reader, bytes[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint64(bytes[:]))
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(reader, payload)
	return payload, err
}
