package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type ImportRepo struct {
	pool *pgxpool.Pool
}

func NewImportRepo(pool *pgxpool.Pool) *ImportRepo {
	return &ImportRepo{pool: pool}
}

var _ repository.ImportRepository = (*ImportRepo)(nil)

func (r *ImportRepo) CreateBatch(ctx context.Context, b *entity.ImportBatch) error {
	const q = `
		INSERT INTO imports (filename, file_type, status, uploaded_by)
		VALUES ($1,$2,$3,$4)
		RETURNING id, created_at`
	return r.pool.QueryRow(ctx, q, b.Filename, b.FileType, string(b.Status), b.UploadedBy).
		Scan(&b.ID, &b.CreatedAt)
}

func (r *ImportRepo) UpdateBatch(ctx context.Context, b *entity.ImportBatch) error {
	const q = `
		UPDATE imports SET
			status=$1, total_rows=$2, processed_rows=$3, failed_rows=$4,
			error_summary=$5, started_at=$6, completed_at=$7
		WHERE id=$8`
	_, err := r.pool.Exec(ctx, q, string(b.Status), b.TotalRows, b.ProcessedRows, b.FailedRows,
		nullableString(b.ErrorSummary), b.StartedAt, b.CompletedAt, b.ID)
	if err != nil {
		return fmt.Errorf("update import batch %s: %w", b.ID, err)
	}
	return nil
}

func (r *ImportRepo) GetBatch(ctx context.Context, id string) (*entity.ImportBatch, error) {
	const q = `
		SELECT id, filename, file_type, status, total_rows, processed_rows, failed_rows,
		       COALESCE(error_summary,''), uploaded_by, started_at, completed_at, created_at
		FROM imports WHERE id=$1`
	b := &entity.ImportBatch{}
	var status string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&b.ID, &b.Filename, &b.FileType, &status, &b.TotalRows, &b.ProcessedRows, &b.FailedRows,
		&b.ErrorSummary, &b.UploadedBy, &b.StartedAt, &b.CompletedAt, &b.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get import batch %s: %w", id, err)
	}
	b.Status = entity.ImportStatus(status)
	return b, nil
}

func (r *ImportRepo) ListRecent(ctx context.Context, limit int) ([]*entity.ImportBatch, error) {
	const q = `
		SELECT id, filename, file_type, status, total_rows, processed_rows, failed_rows,
		       COALESCE(error_summary,''), uploaded_by, started_at, completed_at, created_at
		FROM imports ORDER BY created_at DESC LIMIT $1`
	rows, err := r.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent imports: %w", err)
	}
	defer rows.Close()

	var out []*entity.ImportBatch
	for rows.Next() {
		b := &entity.ImportBatch{}
		var status string
		if err := rows.Scan(
			&b.ID, &b.Filename, &b.FileType, &status, &b.TotalRows, &b.ProcessedRows, &b.FailedRows,
			&b.ErrorSummary, &b.UploadedBy, &b.StartedAt, &b.CompletedAt, &b.CreatedAt,
		); err != nil {
			return nil, err
		}
		b.Status = entity.ImportStatus(status)
		out = append(out, b)
	}
	return out, rows.Err()
}
