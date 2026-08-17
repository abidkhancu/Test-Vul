package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type RemediationRepo struct {
	pool *pgxpool.Pool
}

func NewRemediationRepo(pool *pgxpool.Pool) *RemediationRepo {
	return &RemediationRepo{pool: pool}
}

var _ repository.RemediationRepository = (*RemediationRepo)(nil)

func (r *RemediationRepo) Create(ctx context.Context, t *entity.RemediationTask) error {
	const q = `
		INSERT INTO remediation_tasks (host_id, rhsa_id, severity, status, approval_required)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q, t.HostID, t.RHSAID, string(t.Severity), string(t.Status), t.ApprovalRequired).
		Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create remediation task: %w", err)
	}

	if len(t.CVEIDs) > 0 {
		batch := &pgx.Batch{}
		for _, cve := range t.CVEIDs {
			batch.Queue(`INSERT INTO cves (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, cve)
			batch.Queue(`INSERT INTO remediation_task_cves (task_id, cve_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, t.ID, cve)
		}
		br := r.pool.SendBatch(ctx, batch)
		defer br.Close()
		for i := 0; i < len(t.CVEIDs)*2; i++ {
			if _, err := br.Exec(); err != nil {
				return fmt.Errorf("link task cves: %w", err)
			}
		}
	}

	if len(t.PackageNames) > 0 {
		batch := &pgx.Batch{}
		for _, pkg := range t.PackageNames {
			batch.Queue(`INSERT INTO remediation_task_packages (task_id, package_name) VALUES ($1,$2) ON CONFLICT DO NOTHING`, t.ID, pkg)
		}
		br := r.pool.SendBatch(ctx, batch)
		defer br.Close()
		for i := 0; i < len(t.PackageNames); i++ {
			if _, err := br.Exec(); err != nil {
				return fmt.Errorf("link task packages: %w", err)
			}
		}
	}

	return nil
}

func (r *RemediationRepo) Get(ctx context.Context, id string) (*entity.RemediationTask, error) {
	const q = `
		SELECT id, host_id, rhsa_id, severity, status, last_verified_at, COALESCE(verification_notes,''),
		       approval_required, approved_by, approved_at, rejected_reason, scheduled_for, created_at, updated_at
		FROM remediation_tasks WHERE id=$1`
	t := &entity.RemediationTask{}
	var severity, status string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&t.ID, &t.HostID, &t.RHSAID, &severity, &status, &t.LastVerifiedAt, &t.VerificationNotes,
		&t.ApprovalRequired, &t.ApprovedBy, &t.ApprovedAt, &t.RejectedReason, &t.ScheduledFor,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get remediation task %s: %w", id, err)
	}
	t.Severity = entity.Severity(severity)
	t.Status = entity.RemediationStatus(status)

	if err := r.populateRelations(ctx, []*entity.RemediationTask{t}); err != nil {
		return nil, fmt.Errorf("populate cve/package relations for task %s: %w", id, err)
	}
	return t, nil
}

// populateRelations fills in CVEIDs/PackageNames/FindingIDs from the
// remediation_task_cves/remediation_task_packages/scanner_findings
// join tables, batched across all tasks passed in (WHERE task_id =
// ANY($1)) rather than one query per task.
//
// This matters beyond just API completeness: usecase/ssh.Verifier's
// verifyCVETask reads task.PackageNames to know which packages to
// check over SSH for CVE-only tasks (ones with no RHSA yet) — if
// PackageNames comes back empty because this wasn't populated,
// verification silently no-ops for that task ("no package name
// extracted... needs manual triage") even though the correlation
// engine correctly recorded real package names for it.
func (r *RemediationRepo) populateRelations(ctx context.Context, tasks []*entity.RemediationTask) error {
	if len(tasks) == 0 {
		return nil
	}
	byID := make(map[string]*entity.RemediationTask, len(tasks))
	ids := make([]string, 0, len(tasks))
	for _, t := range tasks {
		byID[t.ID] = t
		ids = append(ids, t.ID)
	}

	cveRows, err := r.pool.Query(ctx, `SELECT task_id, cve_id FROM remediation_task_cves WHERE task_id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("query remediation_task_cves: %w", err)
	}
	for cveRows.Next() {
		var taskID, cveID string
		if err := cveRows.Scan(&taskID, &cveID); err != nil {
			cveRows.Close()
			return err
		}
		if t, ok := byID[taskID]; ok {
			t.CVEIDs = append(t.CVEIDs, cveID)
		}
	}
	cveRows.Close()
	if err := cveRows.Err(); err != nil {
		return err
	}

	pkgRows, err := r.pool.Query(ctx, `SELECT task_id, package_name FROM remediation_task_packages WHERE task_id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("query remediation_task_packages: %w", err)
	}
	for pkgRows.Next() {
		var taskID, pkg string
		if err := pkgRows.Scan(&taskID, &pkg); err != nil {
			pkgRows.Close()
			return err
		}
		if t, ok := byID[taskID]; ok {
			t.PackageNames = append(t.PackageNames, pkg)
		}
	}
	pkgRows.Close()
	if err := pkgRows.Err(); err != nil {
		return err
	}

	findingRows, err := r.pool.Query(ctx, `SELECT remediation_task_id, id FROM scanner_findings WHERE remediation_task_id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("query constituent findings: %w", err)
	}
	for findingRows.Next() {
		var taskID, findingID string
		if err := findingRows.Scan(&taskID, &findingID); err != nil {
			findingRows.Close()
			return err
		}
		if t, ok := byID[taskID]; ok {
			t.FindingIDs = append(t.FindingIDs, findingID)
		}
	}
	findingRows.Close()
	return findingRows.Err()
}

// FindOpenByHostAndTarget backs the correlation engine's dedup logic.
// When rhsaID is set, it matches the DB's partial unique index
// directly. When rhsaID is nil, it falls back to matching a task that
// covers exactly the same CVE set for that host (order-independent).
func (r *RemediationRepo) FindOpenByHostAndTarget(ctx context.Context, hostID string, rhsaID *string, cveIDs []string) (*entity.RemediationTask, error) {
	if rhsaID != nil {
		const q = `
			SELECT id FROM remediation_tasks
			WHERE host_id=$1 AND rhsa_id=$2
			  AND status NOT IN ('remediated','already_remediated','not_applicable','rejected')
			LIMIT 1`
		var id string
		err := r.pool.QueryRow(ctx, q, hostID, *rhsaID).Scan(&id)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return r.Get(ctx, id)
	}

	if len(cveIDs) == 0 {
		return nil, nil
	}
	const q = `
		SELECT rt.id
		FROM remediation_tasks rt
		JOIN (
			SELECT task_id, array_agg(cve_id ORDER BY cve_id) AS cves
			FROM remediation_task_cves
			GROUP BY task_id
		) c ON c.task_id = rt.id
		WHERE rt.host_id = $1 AND rt.rhsa_id IS NULL
		  AND rt.status NOT IN ('remediated','already_remediated','not_applicable','rejected')
		  AND c.cves = $2
		LIMIT 1`
	sorted := append([]string(nil), cveIDs...)
	// caller (correlation engine) already sorts; kept defensive here too
	var id string
	err := r.pool.QueryRow(ctx, q, hostID, sorted).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return r.Get(ctx, id)
}

func (r *RemediationRepo) Update(ctx context.Context, t *entity.RemediationTask) error {
	const q = `
		UPDATE remediation_tasks SET
			severity=$1, status=$2, last_verified_at=$3, verification_notes=$4,
			scheduled_for=$5, updated_at=now()
		WHERE id=$6`
	_, err := r.pool.Exec(ctx, q, string(t.Severity), string(t.Status), t.LastVerifiedAt, t.VerificationNotes, t.ScheduledFor, t.ID)
	return err
}

func (r *RemediationRepo) UpdateStatus(ctx context.Context, id string, status entity.RemediationStatus) error {
	_, err := r.pool.Exec(ctx, `UPDATE remediation_tasks SET status=$1, updated_at=now() WHERE id=$2`, string(status), id)
	return err
}

func (r *RemediationRepo) List(ctx context.Context, f repository.RemediationFilter) ([]*entity.RemediationTask, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.Status != "" {
		where += " AND status = " + arg(string(f.Status))
	}
	if f.Severity != "" {
		where += " AND severity = " + arg(string(f.Severity))
	}
	if f.HostID != "" {
		where += " AND host_id = " + arg(f.HostID)
	}

	page, pageSize := normalizePage(f.Page, f.PageSize)
	offset := (page - 1) * pageSize

	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM remediation_tasks "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count remediation tasks: %w", err)
	}

	listArgs := append(append([]interface{}{}, args...), pageSize, offset)
	listQ := fmt.Sprintf(`
		SELECT id, host_id, rhsa_id, severity, status, last_verified_at, COALESCE(verification_notes,''),
		       approval_required, approved_by, approved_at, rejected_reason, scheduled_for, created_at, updated_at
		FROM remediation_tasks %s
		ORDER BY
			CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			created_at DESC
		LIMIT $%d OFFSET $%d`, where, len(args)+1, len(args)+2)

	rows, err := r.pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list remediation tasks: %w", err)
	}
	defer rows.Close()

	var out []*entity.RemediationTask
	for rows.Next() {
		t := &entity.RemediationTask{}
		var severity, status string
		if err := rows.Scan(
			&t.ID, &t.HostID, &t.RHSAID, &severity, &status, &t.LastVerifiedAt, &t.VerificationNotes,
			&t.ApprovalRequired, &t.ApprovedBy, &t.ApprovedAt, &t.RejectedReason, &t.ScheduledFor,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		t.Severity = entity.Severity(severity)
		t.Status = entity.RemediationStatus(status)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	if err := r.populateRelations(ctx, out); err != nil {
		return nil, 0, fmt.Errorf("populate cve/package relations: %w", err)
	}

	return out, total, nil
}

// Approve is the single write path for moving a task from
// pending_approval to approved. It requires approvedBy to be set —
// callers (the HTTP handler) must have already verified the acting
// user holds the patch_approver or administrator role; this method
// does not re-check RBAC, it only refuses to write an approval
// without an actor.
func (r *RemediationRepo) Approve(ctx context.Context, id, approvedBy string) error {
	if approvedBy == "" {
		return fmt.Errorf("refusing to approve remediation task %s without an approving user", id)
	}
	const q = `
		UPDATE remediation_tasks
		SET status='approved', approved_by=$1, approved_at=now(), updated_at=now()
		WHERE id=$2 AND status='pending_approval'`
	tag, err := r.pool.Exec(ctx, q, approvedBy, id)
	if err != nil {
		return fmt.Errorf("approve task %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("task %s was not in pending_approval state (concurrent update or already actioned)", id)
	}
	return nil
}

func (r *RemediationRepo) Reject(ctx context.Context, id, rejectedBy, reason string) error {
	const q = `
		UPDATE remediation_tasks
		SET status='rejected', approved_by=$1, rejected_reason=$2, updated_at=now()
		WHERE id=$3 AND status='pending_approval'`
	tag, err := r.pool.Exec(ctx, q, rejectedBy, reason, id)
	if err != nil {
		return fmt.Errorf("reject task %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("task %s was not in pending_approval state (concurrent update or already actioned)", id)
	}
	return nil
}
