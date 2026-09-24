package bruecke

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateWireGuardKeyPair() (string, string, error) {
	var privateBytes [32]byte
	if _, err := rand.Read(privateBytes[:]); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}

	privateBytes[0] &= 248
	privateBytes[31] &= 127
	privateBytes[31] |= 64

	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes[:])
	if err != nil {
		return "", "", fmt.Errorf("load private key: %w", err)
	}

	private := base64.StdEncoding.EncodeToString(privateBytes[:])
	public := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	return private, public, nil
}
