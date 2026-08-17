package ssh

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ubank/vuln-platform/internal/crypto"
	"github.com/ubank/vuln-platform/internal/domain/entity"
)

// DialerConfig mirrors config.Config.SSH — kept as its own small
// struct so this package doesn't need to import internal/config
// directly (keeps the dependency graph pointing inward, per hexagonal
// architecture: usecase packages shouldn't depend on the app's config
// package, just on plain values passed in).
type DialerConfig struct {
	ConnectTimeout     time.Duration
	CommandTimeout     time.Duration
	MaxRetries         int
	StrictHostKeyCheck bool
	MaxConcurrent      int // global cap across all verification jobs
}

// Dialer establishes SSH connections to managed hosts, decrypting
// credentials only for the duration of the dial and never persisting
// or logging plaintext secrets. It pools live connections per host so
// a verification pass touching many packages/RHSAs on the same host
// doesn't pay a fresh TCP+SSH handshake per command.
type Dialer struct {
	cfg    DialerConfig
	cipher *crypto.CredentialCipher
	sem    chan struct{} // global concurrency limiter

	mu   sync.Mutex
	pool map[string]*pooledConn // keyed by host.ID
}

type pooledConn struct {
	client   *ssh.Client
	lastUsed time.Time
}

func NewDialer(cfg DialerConfig, cipher *crypto.CredentialCipher) *Dialer {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 50
	}
	return &Dialer{
		cfg:    cfg,
		cipher: cipher,
		sem:    make(chan struct{}, cfg.MaxConcurrent),
		pool:   make(map[string]*pooledConn),
	}
}

// HostKeyRegistry resolves the expected fingerprint for a host so the
// dialer can enforce strict host key checking rather than trusting on
// first use. Backed by hosts.host_key_fingerprint in Postgres;
// implementations should treat a mismatch as a hard failure, not a
// warning — this is what stands between "verified against the real
// host" and "verified against something on the network claiming to
// be the host."
type HostKeyRegistry interface {
	ExpectedFingerprint(hostID string) (string, error)
}

// Connect returns a live *ssh.Client for the given host, using a
// pooled connection if one exists and is still healthy, otherwise
// dialing fresh (optionally via a jump host) with retry-with-backoff.
// credential must already be decrypted by the caller's use of
// crypto.CredentialCipher — see resolveAuthMethod, which is the only
// function in this package that touches plaintext secret bytes, and
// zeroes them immediately after building the ssh.AuthMethod.
func (d *Dialer) Connect(ctx context.Context, host *entity.Host, credential *entity.Credential, keys HostKeyRegistry) (*ssh.Client, error) {
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if c := d.pooledClient(host.ID); c != nil {
		return c, nil
	}

	authMethod, err := d.resolveAuthMethod(credential)
	if err != nil {
		return nil, fmt.Errorf("resolve auth method for host %s: %w", host.ID, err)
	}

	hostKeyCallback, err := d.hostKeyCallback(host, keys)
	if err != nil {
		return nil, err
	}

	sshCfg := &ssh.ClientConfig{
		User:            host.SSHUser,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
		Timeout:         d.cfg.ConnectTimeout,
	}

	addr := net.JoinHostPort(host.SSHHost, portOrDefault(host.SSHPort))

	var client *ssh.Client
	var dialErr error
	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * 2 * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		if host.JumpHostID != nil {
			client, dialErr = d.dialViaJumpHost(ctx, host, sshCfg, addr, keys)
		} else {
			client, dialErr = dialDirect(ctx, addr, sshCfg)
		}
		if dialErr == nil {
			break
		}
	}
	if dialErr != nil {
		return nil, fmt.Errorf("ssh dial %s (%s) after %d attempts: %w", host.Hostname, addr, d.cfg.MaxRetries+1, dialErr)
	}

	d.mu.Lock()
	d.pool[host.ID] = &pooledConn{client: client, lastUsed: time.Now()}
	d.mu.Unlock()

	return client, nil
}

func dialDirect(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// dialViaJumpHost opens a connection to the jump host first (using
// the jump host's own registered credential — resolved by the caller
// via the host repository, since Dialer itself has no DB access),
// then tunnels a TCP stream to the target through it.
//
// NOTE: this scaffold's signature takes the jump host purely as an ID
// reference; wiring it to actually fetch the jump host's Host+
// Credential records belongs in the Verifier (which has repository
// access) rather than here, to keep Dialer free of DB dependencies.
// See Verifier.dialWithJumpHost in verifier.go for that composition.
func (d *Dialer) dialViaJumpHost(ctx context.Context, host *entity.Host, cfg *ssh.ClientConfig, addr string, keys HostKeyRegistry) (*ssh.Client, error) {
	return nil, fmt.Errorf("host %s requires a jump host: call Verifier.ConnectViaJumpHost instead of Dialer.Connect directly", host.ID)
}

func (d *Dialer) pooledClient(hostID string) *ssh.Client {
	d.mu.Lock()
	defer d.mu.Unlock()
	pc, ok := d.pool[hostID]
	if !ok {
		return nil
	}
	// Cheap liveness check: a closed client will error on this.
	if _, _, err := pc.client.SendRequest("keepalive@vuln-platform", true, nil); err != nil {
		delete(d.pool, hostID)
		return nil
	}
	pc.lastUsed = time.Now()
	return pc.client
}

// CloseIdle closes and evicts pooled connections idle longer than
// maxIdle. Intended to be run on a ticker from the verification
// worker so long-lived connections don't accumulate across many
// verification passes.
func (d *Dialer) CloseIdle(maxIdle time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for id, pc := range d.pool {
		if now.Sub(pc.lastUsed) > maxIdle {
			_ = pc.client.Close()
			delete(d.pool, id)
		}
	}
}

// resolveAuthMethod is the only place in this package that handles
// plaintext credential bytes. It decrypts, builds the ssh.AuthMethod,
// then zeroes the plaintext buffer before returning. Never add a log
// statement anywhere in or near this function.
func (d *Dialer) resolveAuthMethod(credential *entity.Credential) (ssh.AuthMethod, error) {
	toDecrypt := credentialToDecrypt(credential)
	plaintext, err := d.cipher.Decrypt(&toDecrypt)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(plaintext)

	switch credential.AuthType {
	case entity.SSHAuthPassword:
		pw := string(plaintext)
		return ssh.Password(pw), nil
	case entity.SSHAuthKey:
		signer, err := ssh.ParsePrivateKey(plaintext)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	default:
		return nil, fmt.Errorf("unsupported auth type %q", credential.AuthType)
	}
}

func credentialToDecrypt(c *entity.Credential) crypto.EncryptedCredential {
	return crypto.EncryptedCredential{
		Blob:            c.EncryptedBlob,
		Nonce:           c.Nonce,
		EncryptionKeyID: c.EncryptionKeyID,
	}
}

// hostKeyCallback enforces strict host key verification by default —
// StrictHostKeyCheck must be explicitly set to false (dev/lab only)
// to fall back to InsecureIgnoreHostKey, and that path logs loudly at
// the call site (see Verifier) rather than silently trusting.
func (d *Dialer) hostKeyCallback(host *entity.Host, keys HostKeyRegistry) (ssh.HostKeyCallback, error) {
	if !d.cfg.StrictHostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	expected, err := keys.ExpectedFingerprint(host.ID)
	if err != nil {
		return nil, fmt.Errorf("no registered host key fingerprint for host %s and strict checking is enabled: %w", host.ID, err)
	}
	if expected == "" {
		return nil, fmt.Errorf("host %s has no registered host key fingerprint; register one (e.g. via a supervised first-connect) before strict verification can run", host.ID)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			return fmt.Errorf("host key mismatch for %s: expected %s, got %s — refusing connection (possible MITM or host rebuild not yet re-registered)", hostname, expected, got)
		}
		return nil
	}, nil
}

func portOrDefault(port int) string {
	if port <= 0 {
		return "22"
	}
	return fmt.Sprintf("%d", port)
}
