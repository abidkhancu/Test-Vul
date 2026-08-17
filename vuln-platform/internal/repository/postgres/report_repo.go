package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type ReportRepo struct {
	pool *pgxpool.Pool
}

func NewReportRepo(pool *pgxpool.Pool) *ReportRepo {
	return &ReportRepo{pool: pool}
}

var _ repository.ReportRepository = (*ReportRepo)(nil)

func (r *ReportRepo) Create(ctx context.Context, rep *entity.Report) error {
	const q = `
		INSERT INTO reports (report_type, format, storage_path, generated_by, filters_json)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::jsonb)
		RETURNING id, created_at`
	return r.pool.QueryRow(ctx, q, string(rep.ReportType), string(rep.Format), rep.StoragePath, rep.GeneratedBy, rep.FiltersJSON).
		Scan(&rep.ID, &rep.CreatedAt)
}

func (r *ReportRepo) Get(ctx context.Context, id string) (*entity.Report, error) {
	const q = `
		SELECT id, report_type, format, storage_path, generated_by, COALESCE(filters_json::text,''), created_at
		FROM reports WHERE id = $1`
	rep := &entity.Report{}
	var reportType, format string
	if err := r.pool.QueryRow(ctx, q, id).Scan(
		&rep.ID, &reportType, &format, &rep.StoragePath, &rep.GeneratedBy, &rep.FiltersJSON, &rep.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("get report %s: %w", id, err)
	}
	rep.ReportType = entity.ReportType(reportType)
	rep.Format = entity.ReportFormat(format)
	return rep, nil
}

func (r *ReportRepo) List(ctx context.Context, reportType entity.ReportType, limit int) ([]*entity.Report, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `
		SELECT id, report_type, format, storage_path, generated_by, COALESCE(filters_json::text,''), created_at
		FROM reports`
	args := []interface{}{}
	if reportType != "" {
		q += " WHERE report_type = $1"
		args = append(args, string(reportType))
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d", limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()

	var out []*entity.Report
	for rows.Next() {
		rep := &entity.Report{}
		var rt, format string
		if err := rows.Scan(&rep.ID, &rt, &format, &rep.StoragePath, &rep.GeneratedBy, &rep.FiltersJSON, &rep.CreatedAt); err != nil {
			return nil, err
		}
		rep.ReportType = entity.ReportType(rt)
		rep.Format = entity.ReportFormat(format)
		out = append(out, rep)
	}
	return out, rows.Err()
}
