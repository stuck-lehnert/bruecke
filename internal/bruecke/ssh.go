package bruecke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHServer deliberately implements only RFC 4254 direct-tcpip channels. There
// is no session handler, command interpreter, PTY, subsystem or remote listener.
type SSHServer struct {
	config    *ssh.ServerConfig
	clients   ClientRepository
	roots     RootRepository
	remote    RemoteSubnetRepository
	logger    Logger
	addresses sshAddressManager
	dial      func(context.Context, netip.Addr, netip.Addr, uint32) (net.Conn, error)
	mu        sync.Mutex
	listener  net.Listener
	closed    bool
	raw       map[net.Conn]struct{}
	active    map[string]map[*ssh.ServerConn]struct{}
	leases    map[string]Client
	last      map[string]time.Time
	wg        sync.WaitGroup
}

func NewSSHServer(cfg Config, clients ClientRepository, roots RootRepository, remote RemoteSubnetRepository, logger Logger) (*SSHServer, error) {
	signer, err := loadSSHHostKey(cfg.SSHHostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	if err := prepareSSHNetwork(); err != nil {
		return nil, fmt.Errorf("SSH source IP interface: %w", err)
	}
	return newSSHServer(signer, clients, roots, remote, logger, sshNetwork{}), nil
}

func newSSHServer(signer ssh.Signer, clients ClientRepository, roots RootRepository, remote RemoteSubnetRepository, logger Logger, addresses sshAddressManager) *SSHServer {
	s := &SSHServer{
		clients:   clients,
		roots:     roots,
		remote:    remote,
		logger:    logger,
		addresses: addresses,
		dial:      dialSSHForward,
		raw:       map[net.Conn]struct{}{},
		active:    map[string]map[*ssh.ServerConn]struct{}{},
		leases:    map[string]Client{},
		last:      map[string]time.Time{},
	}
	algorithms := ssh.SupportedAlgorithms()
	s.config = &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths,
		MaxAuthTries:            3,
		ServerVersion:           "SSH-2.0-bruecke",
		PublicKeyCallback:       s.authenticate,
	}
	s.config.AddHostKey(signer)
	if logger != nil {
		logger.Printf("SSH host key fingerprint %s", ssh.FingerprintSHA256(signer.PublicKey()))
	}
	return s
}

func (s *SSHServer) authenticate(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	for _, client := range s.clients.Clients() {
		if client.Type != "ssh" || client.Disabled || (meta.User() != client.Hostname && meta.User() != client.ID) {
			continue
		}
		stored, _, err := parseSSHPublicKey(client.PublicKey)
		if err == nil && bytes.Equal(stored.Marshal(), key.Marshal()) {
			if _, err := s.roots.Domain(client.DomainID); err == nil {
				return &ssh.Permissions{Extensions: map[string]string{"client-id": client.ID, "public-key": client.PublicKey}}, nil
			}
		}
	}
	return nil, errors.New("public key not authorized")
}

func (s *SSHServer) Serve(listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = listener.Close()
		return net.ErrClosed
	}
	s.listener = listener
	s.mu.Unlock()
	for {
		raw, err := listener.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.raw) >= 128 {
			s.mu.Unlock()
			_ = raw.Close()
			continue
		}
		s.raw[raw] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = raw.Close()
				s.mu.Lock()
				delete(s.raw, raw)
				s.mu.Unlock()
			}()
			s.handle(raw)
		}()
	}
}

func (s *SSHServer) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for conn := range s.raw {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *SSHServer) Disconnect(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.active[id] {
		_ = conn.Close()
	}
}

func (s *SSHServer) Status(id string) (bool, *time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.last[id]
	if !ok {
		return false, nil
	}
	return len(s.active[id]) > 0, &last
}

func (s *SSHServer) register(conn *ssh.ServerConn) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, err := s.clients.Client(conn.Permissions.Extensions["client-id"])
	if err != nil || s.closed || client.Disabled || client.Type != "ssh" || client.PublicKey != conn.Permissions.Extensions["public-key"] {
		return Client{}, errors.New("client no longer authorized")
	}
	if len(s.active[client.ID]) >= 4 {
		return Client{}, errors.New("too many connections for client")
	}
	if lease, ok := s.leases[client.ID]; ok &&
		(lease.PublicKey != client.PublicKey || lease.IP != client.IP || lease.IPv6 != client.IPv6) {
		return Client{}, errors.New("previous client identity is still closing")
	}
	if len(s.active[client.ID]) == 0 {
		// Deletion can release a pool address before the old connection has
		// finished closing. Do not reuse its local IP until cleanup completes.
		for _, lease := range s.leases {
			if lease.IP == client.IP || (client.IPv6 != "" && lease.IPv6 == client.IPv6) {
				return Client{}, errors.New("source IP is still in use by a closing connection")
			}
		}
		if err := s.addresses.Add(client); err != nil {
			return Client{}, err
		}
		s.leases[client.ID] = client
		s.active[client.ID] = map[*ssh.ServerConn]struct{}{}
	}
	s.active[client.ID][conn] = struct{}{}
	s.last[client.ID] = time.Now().UTC()
	return client, nil
}

func (s *SSHServer) unregister(client Client, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active[client.ID], conn)
	if len(s.active[client.ID]) == 0 {
		delete(s.active, client.ID)
		if err := s.addresses.Remove(client); err != nil && s.logger != nil {
			s.logger.Printf("SSH source IP cleanup client=%s: %v", client.ID, err)
		}
		delete(s.leases, client.ID)
	}
}

func (s *SSHServer) handle(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = raw.SetDeadline(time.Time{})
	client, err := s.register(conn)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("SSH connection rejected: %v", err)
		}
		return
	}
	defer s.unregister(client, conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for req := range requests {
			// Keepalives do not grant any capability. All forwarding/global
			// requests, including tcpip-forward and streamlocal, are refused.
			_ = req.Reply(req.Type == "keepalive@openssh.com" && len(req.Payload) == 0, nil)
		}
		cancel()
	}()
	go s.monitor(ctx, conn, client)
	var forwards sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		forwards.Wait()
	}()
	slots := make(chan struct{}, 32)
	for channel := range channels {
		if channel.ChannelType() != "direct-tcpip" {
			_ = channel.Reject(ssh.UnknownChannelType, "only direct TCP forwarding is supported")
			continue
		}
		select {
		case slots <- struct{}{}:
			forwards.Add(1)
			go func(channel ssh.NewChannel) {
				defer forwards.Done()
				defer func() { <-slots }()
				s.forward(ctx, client, channel)
			}(channel)
		default:
			_ = channel.Reject(ssh.ResourceShortage, "channel limit reached")
		}
	}
}

func (s *SSHServer) monitor(ctx context.Context, conn *ssh.ServerConn, client Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := s.clients.Client(client.ID)
			if err != nil || current.Disabled || current.PublicKey != client.PublicKey {
				_ = conn.Close()
				return
			}
			done := make(chan struct{})
			go func() {
				_, _, _ = conn.SendRequest("keepalive@openssh.com", true, nil)
				close(done)
			}()
			timer := time.NewTimer(10 * time.Second)
			select {
			case <-done:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				_ = conn.Close()
				return
			}
		}
	}
}

type sshDirectTCPIP struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (s *SSHServer) forward(ctx context.Context, identity Client, request ssh.NewChannel) {
	id := identity.ID
	var payload sshDirectTCPIP
	if err := ssh.Unmarshal(request.ExtraData(), &payload); err != nil || payload.Port == 0 || payload.Port > 65535 || len(payload.Host) > 253 {
		_ = request.Reject(ssh.ConnectionFailed, "invalid forwarding destination")
		return
	}
	client, err := s.clients.Client(id)
	if err != nil || client.Disabled || client.Type != "ssh" || client.PublicKey != identity.PublicKey || client.IP != identity.IP || client.IPv6 != identity.IPv6 {
		_ = request.Reject(ssh.Prohibited, "client disabled")
		return
	}
	target, ok := s.destination(client, payload.Host)
	if !ok {
		_ = request.Reject(ssh.Prohibited, "destination not allowed")
		return
	}
	source, err := netip.ParseAddr(client.IP)
	if target.Is6() {
		source, err = netip.ParseAddr(client.IPv6)
	}
	if err != nil {
		_ = request.Reject(ssh.ConnectionFailed, "source IP unavailable")
		return
	}
	upstream, err := s.dial(ctx, source, target, payload.Port)
	if err != nil {
		_ = request.Reject(ssh.ConnectionFailed, "destination unavailable")
		return
	}
	defer upstream.Close()
	channel, requests, err := request.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	done := make(chan struct{})
	defer close(done)
	// Enforce revocation on already-open forwards too, including group/subnet
	// changes. Never resolve a hostname again during a connection.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				_ = upstream.Close()
				_ = channel.Close()
				return
			case <-ticker.C:
				current, err := s.clients.Client(id)
				if err != nil || current.Disabled || current.PublicKey != identity.PublicKey || current.IP != identity.IP || current.IPv6 != identity.IPv6 || !s.allowed(current, target) {
					_ = upstream.Close()
					_ = channel.Close()
					return
				}
			}
		}
	}()
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, channel)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(copied)
	}()
	_, _ = io.Copy(channel, upstream)
	_ = channel.CloseWrite()
	_ = channel.Close()
	_ = upstream.Close()
	<-copied
}

func (s *SSHServer) destination(client Client, host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		return addr, s.allowed(client, addr)
	}
	// Domain client names are resolved internally, not via the host's resolver:
	// no DNS rebinding, external DNS leakage or arbitrary hostname proxying.
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain, err := s.roots.Domain(client.DomainID)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, peer := range s.clients.Clients() {
		if peer.DomainID == client.DomainID && !peer.Disabled && peer.Type != "ssh" &&
			(host == peer.Hostname || (domain.SearchDomain != "" && host == peer.Hostname+"."+domain.SearchDomain)) {
			addr, err := netip.ParseAddr(peer.IP)
			return addr, err == nil && s.allowed(client, addr)
		}
	}
	return netip.Addr{}, false
}

func (s *SSHServer) allowed(client Client, target netip.Addr) bool {
	if client.Disabled || client.Type != "ssh" || !target.IsValid() || target.Zone() != "" ||
		target.IsLoopback() || target.IsUnspecified() || target.IsMulticast() || target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast() {
		return false
	}
	if _, err := s.roots.Domain(client.DomainID); err != nil {
		return false
	}
	// Never reach local host services, even if a remote subnet is overly broad.
	if addrs, err := net.InterfaceAddrs(); err != nil {
		return false
	} else {
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err == nil && prefix.Addr().Unmap() == target {
				return false
			}
		}
	}
	for _, domain := range s.roots.Domains() {
		if target.String() == domain.WGServerIP || target.String() == domain.WGIPv6ServerIP {
			return false
		}
	}
	for _, peer := range s.clients.Clients() {
		if target.String() == peer.IP || target.String() == peer.IPv6 {
			return peer.DomainID == client.DomainID && !peer.Disabled && peer.Type != "ssh"
		}
	}
	// A broad remote route must not bypass domain isolation or grant access to
	// unallocated VPN addresses.
	for _, domain := range s.roots.Domains() {
		for _, cidr := range []string{domain.WGCIDR, domain.WGIPv6CIDR} {
			if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(target) {
				return false
			}
		}
	}
	if s.remote != nil {
		for _, spec := range s.remote.Specs() {
			if !spec.Enabled || !remoteSubnetAllowedForClient(spec, client) {
				continue
			}
			for _, cidr := range spec.Subnets {
				prefix, err := netip.ParsePrefix(cidr)
				if err == nil && prefix.Contains(target) {
					return true
				}
			}
		}
	}
	return false
}
