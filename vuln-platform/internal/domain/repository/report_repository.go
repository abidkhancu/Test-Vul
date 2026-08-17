package repository

import (
	"context"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

type ReportRepository interface {
	Create(ctx context.Context, r *entity.Report) error
	Get(ctx context.Context, id string) (*entity.Report, error)
	List(ctx context.Context, reportType entity.ReportType, limit int) ([]*entity.Report, error)
}
