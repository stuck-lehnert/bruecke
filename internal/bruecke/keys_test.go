package bruecke

import (
	"encoding/base64"
	"testing"
)

func TestGenerateWireGuardKeyPair(t *testing.T) {
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	privateBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatalf("private key is not base64: %v", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	if len(privateBytes) != 32 {
		t.Fatalf("private key length=%d, want 32", len(privateBytes))
	}
	if len(publicBytes) != 32 {
		t.Fatalf("public key length=%d, want 32", len(publicBytes))
	}
}
