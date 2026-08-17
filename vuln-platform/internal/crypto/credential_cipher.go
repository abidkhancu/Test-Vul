// Package crypto implements at-rest encryption for SSH credentials.
// Every credential (password or private key) is encrypted with
// AES-256-GCM before it ever reaches the database, and decrypted only
// in-memory, only for the duration of establishing an SSH connection.
// Plaintext credentials must never be logged — see the explicit
// "never log" comments at each call site in usecase/ssh.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeyProvider resolves an encryption key by ID, supporting key
// rotation: old credentials keep working (decrypted with their
// original key) while new writes use the current key. A minimal
// static, single-key implementation is provided below
// (StaticKeyProvider) for environments not yet using Vault; swap in
// a Vault-backed provider without touching CredentialCipher.
type KeyProvider interface {
	// CurrentKeyID returns the key ID that should be used for new
	// encryption operations.
	CurrentKeyID() string
	// Key returns the raw 32-byte AES-256 key for the given key ID.
	Key(keyID string) ([]byte, error)
}

// StaticKeyProvider holds a single key in memory, sourced from
// config.Auth.CredentialEncryptionKey (itself sourced from an env var
// / mounted secret, never committed to a config file). Rotate by
// switching to a provider backed by Vault's transit engine or KMS
// once that integration lands — see spec's "Future Integrations".
type StaticKeyProvider struct {
	keyID string
	key   []byte
}

func NewStaticKeyProvider(keyID string, key []byte) (*StaticKeyProvider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("credential encryption key must be exactly 32 bytes for AES-256, got %d", len(key))
	}
	return &StaticKeyProvider{keyID: keyID, key: key}, nil
}

func (p *StaticKeyProvider) CurrentKeyID() string { return p.keyID }

func (p *StaticKeyProvider) Key(keyID string) ([]byte, error) {
	if keyID != p.keyID {
		return nil, fmt.Errorf("unknown encryption key id %q", keyID)
	}
	return p.key, nil
}

// CredentialCipher encrypts/decrypts SSH credential material.
type CredentialCipher struct {
	keys KeyProvider
}

func NewCredentialCipher(keys KeyProvider) *CredentialCipher {
	return &CredentialCipher{keys: keys}
}

// EncryptedCredential is the ciphertext + metadata persisted to the
// `credentials` table. Plaintext is never a field on this struct.
type EncryptedCredential struct {
	Blob            []byte
	Nonce           []byte
	EncryptionKeyID string
}

// Encrypt seals plaintext (a password or PEM-encoded private key)
// under the current key. Callers must zero the plaintext byte slice
// after calling this where practical (see usecase/ssh for the
// pattern) since Go can't guarantee secure erasure, but zeroing
// reduces the window a secret sits in memory.
func (c *CredentialCipher) Encrypt(plaintext []byte) (*EncryptedCredential, error) {
	keyID := c.keys.CurrentKeyID()
	key, err := c.keys.Key(keyID)
	if err != nil {
		return nil, fmt.Errorf("resolve current encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &EncryptedCredential{Blob: ciphertext, Nonce: nonce, EncryptionKeyID: keyID}, nil
}

// Decrypt opens ciphertext sealed by Encrypt (possibly under an older
// rotated key, resolved via EncryptionKeyID). The returned plaintext
// must be handled per the same "minimize lifetime, zero when done"
// discipline as Encrypt's input — see usecase/ssh.Dialer for the
// only place this should ever be called from.
func (c *CredentialCipher) Decrypt(enc *EncryptedCredential) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("nil encrypted credential")
	}
	key, err := c.keys.Key(enc.EncryptionKeyID)
	if err != nil {
		return nil, fmt.Errorf("resolve encryption key %q: %w", enc.EncryptionKeyID, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Blob, nil)
	if err != nil {
		// Deliberately generic error: never echo ciphertext, nonce,
		// or any derived material into logs/errors that might be
		// captured downstream.
		return nil, errors.New("decrypt credential: authentication failed (wrong key or corrupted data)")
	}
	return plaintext, nil
}

// Zero overwrites a byte slice in place. Best-effort defense in depth
// — the Go runtime/GC can still leave copies elsewhere in memory —
// but call this as soon as a plaintext secret is no longer needed.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
