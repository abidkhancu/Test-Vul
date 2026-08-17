package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HostKeyRegistry implements ssh.HostKeyRegistry against the hosts
// table's host_key_fingerprint column. Registering a fingerprint
// (i.e. writing to that column) should only ever happen through a
// deliberate, audited "register/rotate host key" administrative
// action — never automatically on first connect — since silently
// trusting whatever key a host presents the first time defeats the
// point of strict host key checking.
type HostKeyRegistry struct {
	pool *pgxpool.Pool
}

func NewHostKeyRegistry(pool *pgxpool.Pool) *HostKeyRegistry {
	return &HostKeyRegistry{pool: pool}
}

func (r *HostKeyRegistry) ExpectedFingerprint(hostID string) (string, error) {
	const q = `SELECT COALESCE(host_key_fingerprint, '') FROM hosts WHERE id = $1`
	var fp string
	if err := r.pool.QueryRow(context.Background(), q, hostID).Scan(&fp); err != nil {
		return "", fmt.Errorf("look up host key fingerprint for %s: %w", hostID, err)
	}
	return fp, nil
}

// Register writes the expected fingerprint for a host. Intended to be
// called only from an explicit, RBAC-gated "register host key"
// admin/operator action (see spec's Host management), with the
// fingerprint value itself sourced out-of-band (e.g. read directly
// off the host's console, or from a trusted CMDB) — not from the
// first SSH banner this application happens to see.
func (r *HostKeyRegistry) Register(ctx context.Context, hostID, fingerprint, registeredBy string) error {
	const q = `UPDATE hosts SET host_key_fingerprint = $1, updated_at = now() WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, fingerprint, hostID)
	if err != nil {
		return fmt.Errorf("register host key for %s: %w", hostID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("host %s not found", hostID)
	}
	// Callers should also write an audit_logs entry for this
	// (action="host.register_key") — left to the HTTP handler layer
	// since it has the acting user's identity; this repository method
	// only performs the write.
	_ = registeredBy
	return nil
}
