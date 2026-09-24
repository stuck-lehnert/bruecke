package bruecke

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}

	value := strings.TrimSpace(string(data))
	if value != "" {
		if der, err := base64.StdEncoding.DecodeString(value); err == nil {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return []*x509.Certificate{cert}, nil
		}
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

func pemForCertificate(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
