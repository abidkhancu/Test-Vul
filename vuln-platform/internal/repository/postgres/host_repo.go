package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type HostRepo struct {
	pool *pgxpool.Pool
}

func NewHostRepo(pool *pgxpool.Pool) *HostRepo {
	return &HostRepo{pool: pool}
}

var _ repository.HostRepository = (*HostRepo)(nil)

func (r *HostRepo) Create(ctx context.Context, h *entity.Host) error {
	const q = `
		INSERT INTO hosts (hostname, ip_address, environment, os_family, os_version, status,
		                    ssh_host, ssh_port, ssh_user, jump_host_id, credential_id, host_key_fingerprint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		h.Hostname, nullableString(h.IPAddress), h.Environment, h.OSFamily, h.OSVersion, string(h.Status),
		h.SSHHost, h.SSHPort, h.SSHUser, h.JumpHostID, nullableString(h.CredentialID), h.HostKeyFingerprint,
	).Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt)
}

func (r *HostRepo) Get(ctx context.Context, id string) (*entity.Host, error) {
	const q = `
		SELECT id, hostname, COALESCE(ip_address::text,''), COALESCE(environment,''), COALESCE(os_family,''),
		       COALESCE(os_version,''), status, COALESCE(ssh_host,''), ssh_port, COALESCE(ssh_user,''),
		       jump_host_id, COALESCE(credential_id::text,''), COALESCE(host_key_fingerprint,''),
		       last_seen_at, created_at, updated_at
		FROM hosts WHERE id = $1`
	h := &entity.Host{}
	var status string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.Environment, &h.OSFamily, &h.OSVersion, &status,
		&h.SSHHost, &h.SSHPort, &h.SSHUser, &h.JumpHostID, &h.CredentialID, &h.HostKeyFingerprint,
		&h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get host %s: %w", id, err)
	}
	h.Status = entity.HostStatus(status)
	return h, nil
}

func (r *HostRepo) FindByHostnameOrIP(ctx context.Context, hostnameOrIP string) (*entity.Host, error) {
	const q = `SELECT id FROM hosts WHERE hostname = $1 OR ip_address::text = $1 LIMIT 1`
	var id string
	if err := r.pool.QueryRow(ctx, q, hostnameOrIP).Scan(&id); err != nil {
		return nil, fmt.Errorf("find host %q: %w", hostnameOrIP, err)
	}
	return r.Get(ctx, id)
}

// Upsert matches on (hostname, environment) — the same uniqueness
// constraint enforced at the DB level — so re-importing scanner
// reports that reference an already-known host updates it in place
// instead of creating duplicates.
func (r *HostRepo) Upsert(ctx context.Context, h *entity.Host) error {
	const q = `
		INSERT INTO hosts (hostname, ip_address, environment, os_family, os_version, status,
		                    ssh_host, ssh_port, ssh_user, credential_id, host_key_fingerprint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (hostname, environment) DO UPDATE SET
			ip_address = COALESCE(EXCLUDED.ip_address, hosts.ip_address),
			os_family  = COALESCE(NULLIF(EXCLUDED.os_family, ''), hosts.os_family),
			os_version = COALESCE(NULLIF(EXCLUDED.os_version, ''), hosts.os_version),
			updated_at = now()
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		h.Hostname, nullableString(h.IPAddress), h.Environment, h.OSFamily, h.OSVersion, string(h.Status),
		h.SSHHost, h.SSHPort, h.SSHUser, nullableString(h.CredentialID), h.HostKeyFingerprint,
	).Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt)
}

func (r *HostRepo) UpdateStatus(ctx context.Context, id string, status entity.HostStatus) error {
	_, err := r.pool.Exec(ctx, `UPDATE hosts SET status=$1, last_seen_at=now(), updated_at=now() WHERE id=$2`, string(status), id)
	return err
}

func (r *HostRepo) List(ctx context.Context, f repository.HostFilter) ([]*entity.Host, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.Environment != "" {
		where += " AND environment = " + arg(f.Environment)
	}
	if f.Status != "" {
		where += " AND status = " + arg(string(f.Status))
	}
	if f.Search != "" {
		s := arg("%" + f.Search + "%")
		where += fmt.Sprintf(" AND (hostname ILIKE %s OR ip_address::text ILIKE %s)", s, s)
	}

	page, pageSize := normalizePage(f.Page, f.PageSize)
	offset := (page - 1) * pageSize

	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM hosts "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count hosts: %w", err)
	}

	listArgs := append(append([]interface{}{}, args...), pageSize, offset)
	listQ := fmt.Sprintf(`
		SELECT id, hostname, COALESCE(ip_address::text,''), COALESCE(environment,''), COALESCE(os_family,''),
		       COALESCE(os_version,''), status, COALESCE(ssh_host,''), ssh_port, COALESCE(ssh_user,''),
		       jump_host_id, COALESCE(credential_id::text,''), COALESCE(host_key_fingerprint,''),
		       last_seen_at, created_at, updated_at
		FROM hosts %s
		ORDER BY hostname ASC
		LIMIT $%d OFFSET $%d`, where, len(args)+1, len(args)+2)

	rows, err := r.pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var out []*entity.Host
	for rows.Next() {
		h := &entity.Host{}
		var status string
		if err := rows.Scan(
			&h.ID, &h.Hostname, &h.IPAddress, &h.Environment, &h.OSFamily, &h.OSVersion, &status,
			&h.SSHHost, &h.SSHPort, &h.SSHUser, &h.JumpHostID, &h.CredentialID, &h.HostKeyFingerprint,
			&h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		h.Status = entity.HostStatus(status)
		out = append(out, h)
	}
	return out, total, rows.Err()
}
