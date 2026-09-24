package bruecke

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const enrollmentTTL = 15 * time.Second

type enrollmentHandshake struct {
	ID                  string
	Hostname            string
	DomainID            string
	DomainName          string
	Certificate         *x509.Certificate
	CertificateSubject  string
	CertificateSerial   string
	CertificateNotAfter time.Time
	Payload             []byte
	ExpiresAt           time.Time
}

type enrollStartRequest struct {
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain,omitempty"`
}

type enrollStartResponse struct {
	HandshakeID string    `json:"handshake_id"`
	Hostname    string    `json:"hostname"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type enrollFinishRequest struct {
	HandshakeID    string `json:"handshake_id"`
	Signature      string `json:"signature"`
	Algorithm      string `json:"algorithm,omitempty"`
	ResponseFormat string `json:"response_format,omitempty"`
}

type enrollFinishResponse struct {
	Config        string                   `json:"config"`
	LocalNetworks []DomainLocalNetwork     `json:"local_networks"`
	LocalNetwork  legacyDomainLocalNetwork `json:"local_network"`
	ClientID      string                   `json:"client_id"`
	Hostname      string                   `json:"hostname"`
	Address       string                   `json:"address"`
}

func (s *Server) handleEnrollStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrollStartRequest
	if err := decodeJSON(w, r, &req); err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll start invalid JSON: %v", err)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certs, err := certificatesFromEnrollmentRequest(req)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll start certificate parse failed: %v", err)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cert := certs[0]
	domain, err := s.verifyClientCertificate(cert, certs[1:])
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll start certificate verify failed subject=%s issuer=%s serial=%s: %v", cert.Subject.String(), cert.Issuer.String(), cert.SerialNumber.String(), err)
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	hostname, err := hostnameFromCertificate(cert)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll start hostname failed subject=%s serial=%s: %v", cert.Subject.String(), cert.SerialNumber.String(), err)
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	handshakeID, err := randomBase64(32)
	if err != nil {
		http.Error(w, "challenge creation failed", http.StatusInternalServerError)
		return
	}
	nonce, err := randomBase64(32)
	if err != nil {
		http.Error(w, "challenge creation failed", http.StatusInternalServerError)
		return
	}
	expiresAt := s.now().Add(enrollmentTTL)
	payload := []byte(fmt.Sprintf("bruecke enrollment v1\n%s\n%s\n%s\n%s\n", handshakeID, hostname, domain.ID, nonce))

	handshake := enrollmentHandshake{
		ID:                  handshakeID,
		Hostname:            hostname,
		DomainID:            domain.ID,
		DomainName:          domain.Name,
		Certificate:         cert,
		CertificateSubject:  cert.Subject.String(),
		CertificateSerial:   cert.SerialNumber.String(),
		CertificateNotAfter: cert.NotAfter.UTC(),
		Payload:             payload,
		ExpiresAt:           expiresAt,
	}
	s.storeHandshake(handshake)
	if s.logger != nil {
		s.logger.Printf("enroll start hostname=%s domain=%s handshake=%s expires=%s", hostname, domain.ID, handshakeID, expiresAt.UTC().Format(time.RFC3339))
	}

	writeJSON(w, http.StatusOK, enrollStartResponse{
		HandshakeID: handshakeID,
		Hostname:    hostname,
		Challenge:   base64.StdEncoding.EncodeToString(payload),
		ExpiresAt:   expiresAt,
	})
}

func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrollFinishRequest
	if err := decodeJSON(w, r, &req); err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll finish invalid JSON: %v", err)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	handshake, ok := s.takeHandshake(req.HandshakeID)
	if !ok {
		if s.logger != nil {
			s.logger.Printf("enroll finish handshake missing id=%s", strings.TrimSpace(req.HandshakeID))
		}
		http.Error(w, "handshake not found or expired", http.StatusUnauthorized)
		return
	}
	if !s.now().Before(handshake.ExpiresAt) {
		if s.logger != nil {
			s.logger.Printf("enroll finish handshake expired hostname=%s domain=%s id=%s", handshake.Hostname, handshake.DomainID, req.HandshakeID)
		}
		http.Error(w, "handshake expired", http.StatusUnauthorized)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll finish invalid signature encoding hostname=%s domain=%s: %v", handshake.Hostname, handshake.DomainID, err)
		}
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	if err := verifyChallengeSignature(handshake.Certificate, handshake.Payload, signature, req.Algorithm); err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll finish signature verify failed hostname=%s domain=%s algorithm=%s: %v", handshake.Hostname, handshake.DomainID, req.Algorithm, err)
		}
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	privateKey, publicKey, err := s.keys.GenerateWireGuardKeyPair()
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll finish key generation failed hostname=%s domain=%s: %v", handshake.Hostname, handshake.DomainID, err)
		}
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}

	client, config, localNetworks, err := s.issueClientConfig(r.Context(), Enrollment{
		Hostname:            handshake.Hostname,
		DomainID:            handshake.DomainID,
		DomainName:          handshake.DomainName,
		PublicKey:           publicKey,
		CertificateSubject:  handshake.CertificateSubject,
		CertificateSerial:   handshake.CertificateSerial,
		CertificateNotAfter: handshake.CertificateNotAfter,
		IssuedAt:            s.now(),
	}, privateKey)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("enroll failed hostname=%s: %v", handshake.Hostname, err)
		}
		http.Error(w, "enrollment failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Bruecke-Hostname", client.Hostname)
	w.Header().Set("X-Bruecke-Address", clientAddressLine(client))
	if s.logger != nil {
		s.logger.Printf("issued hostname=%s ip=%s serial=%s", client.Hostname, client.IP, client.CertificateSerial)
	}
	if strings.EqualFold(strings.TrimSpace(req.ResponseFormat), "json") {
		writeJSON(w, http.StatusOK, enrollFinishResponse{Config: config, LocalNetworks: localNetworks, LocalNetwork: legacyLocalNetwork(localNetworks), ClientID: client.ID, Hostname: client.Hostname, Address: clientAddressLine(client)})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, config)
}

func (s *Server) issueClientConfig(ctx context.Context, enrollment Enrollment, privateKey string) (Client, string, []DomainLocalNetwork, error) {
	domain, err := s.domain(enrollment.DomainID)
	if err != nil {
		return Client{}, "", nil, err
	}
	enrollment.DomainID = domain.ID
	enrollment.DomainName = domain.Name
	enrollment.Settings = domain.VPNSettings()
	publicKey := enrollment.PublicKey
	client, err := s.store.Rotate(ctx, enrollment, func(oldPublicKey, allowedIP string, enabled bool) error {
		return s.wg.RotatePeer(ctx, oldPublicKey, publicKey, allowedIP, enabled)
	})
	if err != nil {
		return Client{}, "", nil, err
	}
	if err := s.syncRemoteRuntime(ctx); err != nil {
		return Client{}, "", nil, err
	}
	return client, s.renderClientConfig(privateKey, client), append([]DomainLocalNetwork{}, domain.LocalNetworks...), nil
}

func certificatesFromEnrollmentRequest(req enrollStartRequest) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, raw := range append([]string{req.Certificate}, req.Chain...) {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		parsed, err := parseCertificates([]byte(raw))
		if err != nil {
			return nil, err
		}
		certs = append(certs, parsed...)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("client certificate required")
	}
	return certs, nil
}

func (s *Server) verifyClientCertificate(cert *x509.Certificate, chain []*x509.Certificate) (Domain, error) {
	if s.roots == nil {
		return Domain{}, fmt.Errorf("client CA is not configured")
	}
	domain, err := s.roots.VerifyClientCertificate(cert, chain, s.now())
	if err != nil {
		return Domain{}, err
	}
	return domain, nil
}

func verifyChallengeSignature(cert *x509.Certificate, payload, signature []byte, algorithm string) error {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if algorithm == "" {
		if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			algorithm = "sha256-rsa"
		} else {
			algorithm = "sha256-ecdsa"
		}
	}
	switch algorithm {
	case "sha256-rsa", "sha256-rsa-pkcs1v15", "rsa-sha256":
		return cert.CheckSignature(x509.SHA256WithRSA, payload, signature)
	case "sha256-rsa-pss", "rsa-pss-sha256":
		return cert.CheckSignature(x509.SHA256WithRSAPSS, payload, signature)
	case "sha256-ecdsa", "ecdsa-sha256":
		return cert.CheckSignature(x509.ECDSAWithSHA256, payload, signature)
	default:
		return fmt.Errorf("unsupported signature algorithm")
	}
}

func (s *Server) storeHandshake(handshake enrollmentHandshake) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	s.cleanupHandshakesLocked(s.now())
	key := handshakeKey(handshake.Hostname, handshake.DomainID)
	if oldID, ok := s.hosts[key]; ok {
		delete(s.hids, oldID.ID)
	}
	s.hosts[key] = handshake
	s.hids[handshake.ID] = key
	time.AfterFunc(enrollmentTTL, func() {
		s.expireHandshake(key, handshake.ID)
	})
}

func (s *Server) takeHandshake(id string) (enrollmentHandshake, bool) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	s.cleanupHandshakesLocked(s.now())
	key, ok := s.hids[id]
	if !ok {
		return enrollmentHandshake{}, false
	}
	handshake, ok := s.hosts[key]
	if !ok || handshake.ID != id {
		delete(s.hids, id)
		return enrollmentHandshake{}, false
	}
	delete(s.hosts, key)
	delete(s.hids, id)
	return handshake, true
}

func (s *Server) expireHandshake(key, id string) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	handshake, ok := s.hosts[key]
	if ok && handshake.ID == id {
		delete(s.hosts, key)
		delete(s.hids, id)
	}
}

func (s *Server) cleanupHandshakesLocked(now time.Time) {
	for hostname, handshake := range s.hosts {
		if !now.Before(handshake.ExpiresAt) {
			delete(s.hosts, hostname)
			delete(s.hids, handshake.ID)
		}
	}
}

func handshakeKey(hostname, domainID string) string {
	return clientID(hostname, domainID)
}

func randomBase64(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
