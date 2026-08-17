package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type AuditRepo struct {
	pool *pgxpool.Pool
}

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{pool: pool}
}

var _ repository.AuditRepository = (*AuditRepo)(nil)

// Write inserts one audit log row. There is deliberately no Update or
// Delete method on this repository, and the audit_logs table itself
// has DB-level rules turning UPDATE/DELETE into no-ops (see
// migrations/0001_init_schema.sql) — audit integrity should not
// depend solely on nobody adding a mutating method here later.
func (r *AuditRepo) Write(ctx context.Context, log *entity.AuditLog) error {
	const q = `
		INSERT INTO audit_logs (username, action, host_id, executed_command, exit_code,
		                         execution_time_ms, result, detail, correlation_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, "timestamp"`
	err := r.pool.QueryRow(ctx, q,
		log.Username, log.Action, log.HostID, log.ExecutedCommand, log.ExitCode,
		log.ExecutionTimeMS, log.Result, nullableString(log.Detail), log.CorrelationID,
	).Scan(&log.ID, &log.Timestamp)
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

func (r *AuditRepo) Query(ctx context.Context, f repository.AuditFilter) ([]*entity.AuditLog, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.Username != "" {
		where += " AND username = " + arg(f.Username)
	}
	if f.Action != "" {
		where += " AND action = " + arg(f.Action)
	}
	if f.HostID != "" {
		where += " AND host_id = " + arg(f.HostID)
	}
	if f.From != nil {
		where += " AND \"timestamp\" >= " + arg(*f.From)
	}
	if f.To != nil {
		where += " AND \"timestamp\" <= " + arg(*f.To)
	}

	page, pageSize := normalizePage(f.Page, f.PageSize)
	offset := (page - 1) * pageSize

	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	listArgs := append(append([]interface{}{}, args...), pageSize, offset)
	listQ := fmt.Sprintf(`
		SELECT id, "timestamp", username, action, host_id, executed_command, exit_code,
		       execution_time_ms, result, COALESCE(detail,''), correlation_id
		FROM audit_logs %s
		ORDER BY "timestamp" DESC
		LIMIT $%d OFFSET $%d`, where, len(args)+1, len(args)+2)

	rows, err := r.pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	var out []*entity.AuditLog
	for rows.Next() {
		l := &entity.AuditLog{}
		if err := rows.Scan(
			&l.ID, &l.Timestamp, &l.Username, &l.Action, &l.HostID, &l.ExecutedCommand, &l.ExitCode,
			&l.ExecutionTimeMS, &l.Result, &l.Detail, &l.CorrelationID,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}
