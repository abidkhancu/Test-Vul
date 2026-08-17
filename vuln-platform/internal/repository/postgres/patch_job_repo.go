package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type PatchJobRepo struct {
	pool *pgxpool.Pool
}

func NewPatchJobRepo(pool *pgxpool.Pool) *PatchJobRepo {
	return &PatchJobRepo{pool: pool}
}

var _ repository.PatchJobRepository = (*PatchJobRepo)(nil)

func (r *PatchJobRepo) Create(ctx context.Context, j *entity.PatchJob) error {
	const q = `
		INSERT INTO patch_jobs (remediation_task_id, host_id, rhsa_id, approved_by, approved_at, command, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, created_at`
	return r.pool.QueryRow(ctx, q,
		j.RemediationTaskID, j.HostID, j.RHSAID, j.ApprovedBy, j.ApprovedAt, j.Command, string(j.Status),
	).Scan(&j.ID, &j.CreatedAt)
}

func (r *PatchJobRepo) Update(ctx context.Context, j *entity.PatchJob) error {
	const q = `
		UPDATE patch_jobs SET
			status=$1, exit_code=$2, stdout=$3, stderr=$4, started_at=$5,
			completed_at=$6, post_verify_passed=$7
		WHERE id=$8`
	_, err := r.pool.Exec(ctx, q,
		string(j.Status), j.ExitCode, j.Stdout, j.Stderr, j.StartedAt,
		j.CompletedAt, j.PostVerifyPassed, j.ID,
	)
	if err != nil {
		return fmt.Errorf("update patch job %s: %w", j.ID, err)
	}
	return nil
}

func (r *PatchJobRepo) Get(ctx context.Context, id string) (*entity.PatchJob, error) {
	const q = `
		SELECT id, remediation_task_id, host_id, rhsa_id, approved_by, approved_at, command, status,
		       exit_code, COALESCE(stdout,''), COALESCE(stderr,''), started_at, completed_at,
		       post_verify_passed, maintenance_window_id, created_at
		FROM patch_jobs WHERE id=$1`
	j := &entity.PatchJob{}
	var status string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&j.ID, &j.RemediationTaskID, &j.HostID, &j.RHSAID, &j.ApprovedBy, &j.ApprovedAt, &j.Command, &status,
		&j.ExitCode, &j.Stdout, &j.Stderr, &j.StartedAt, &j.CompletedAt,
		&j.PostVerifyPassed, &j.MaintenanceWindowID, &j.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get patch job %s: %w", id, err)
	}
	j.Status = entity.PatchJobStatus(status)
	return j, nil
}

func (r *PatchJobRepo) ListByTask(ctx context.Context, taskID string) ([]*entity.PatchJob, error) {
	const q = `
		SELECT id, remediation_task_id, host_id, rhsa_id, approved_by, approved_at, command, status,
		       exit_code, COALESCE(stdout,''), COALESCE(stderr,''), started_at, completed_at,
		       post_verify_passed, maintenance_window_id, created_at
		FROM patch_jobs WHERE remediation_task_id=$1 ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, taskID)
	if err != nil {
		return nil, fmt.Errorf("list patch jobs for task %s: %w", taskID, err)
	}
	defer rows.Close()

	var out []*entity.PatchJob
	for rows.Next() {
		j := &entity.PatchJob{}
		var status string
		if err := rows.Scan(
			&j.ID, &j.RemediationTaskID, &j.HostID, &j.RHSAID, &j.ApprovedBy, &j.ApprovedAt, &j.Command, &status,
			&j.ExitCode, &j.Stdout, &j.Stderr, &j.StartedAt, &j.CompletedAt,
			&j.PostVerifyPassed, &j.MaintenanceWindowID, &j.CreatedAt,
		); err != nil {
			return nil, err
		}
		j.Status = entity.PatchJobStatus(status)
		out = append(out, j)
	}
	return out, rows.Err()
}
