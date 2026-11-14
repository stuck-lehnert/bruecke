package bruecke

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Accept one bare OpenSSH public key, never authorized_keys options or certificates.
func parseSSHPublicKey(raw string) (ssh.PublicKey, string, error) {
	if len(raw) > 16*1024 {
		return nil, "", fmt.Errorf("SSH public key is too large")
	}
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "\r\n") {
		return nil, "", fmt.Errorf("provide one single-line OpenSSH public key")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, "", fmt.Errorf("provide exactly one OpenSSH public key without authorized_keys options")
	}
	switch key.Type() {
	case ssh.KeyAlgoRSA:
		pub := key.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)
		if pub.N.BitLen() < 2048 || pub.N.BitLen() > 8192 {
			return nil, "", fmt.Errorf("RSA keys must have 2048 to 8192 bits")
		}
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519:
	default:
		return nil, "", fmt.Errorf("supported SSH keys: RSA (2048–8192 bits), ECDSA (256/384/521), Ed25519")
	}
	return key, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}

func loadSSHHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "bruecke jump host")
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(block)
		// O_EXCL prevents silently replacing an existing host identity.
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(data)
		err = file.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("SSH host private key must not be accessible to group/others: %s", path)
	}
	return ssh.ParsePrivateKey(data)
}
