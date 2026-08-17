package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type FindingRepo struct {
	pool *pgxpool.Pool
}

func NewFindingRepo(pool *pgxpool.Pool) *FindingRepo {
	return &FindingRepo{pool: pool}
}

var _ repository.FindingRepository = (*FindingRepo)(nil)

// BulkInsert uses pgx's COPY protocol rather than N individual
// INSERTs, which is the difference between minutes and hours when
// importing 100k+ row scanner reports. Extracted CVE/RHSA/package
// references are inserted in a second pass via small batched
// multi-row INSERTs against the join tables, guarded by an
// ON CONFLICT DO NOTHING since the referenced cve/rhsa rows may not
// exist yet at import time (they get created by the extraction/RHSA
// sync jobs) -- callers should treat missing FK targets there as
// expected during bulk import, not an error.
func (r *FindingRepo) BulkInsert(ctx context.Context, findings []*entity.ScannerFinding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows := make([][]interface{}, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, []interface{}{
			f.ImportID, f.Source, f.SourceID, f.Name, f.Description, f.Impact, f.Solution,
			f.AssessmentType, f.Comments, f.ClosureByException, string(f.Severity), string(f.Status),
			nullableString(f.HostID), f.HostRaw, f.ReportedOn, f.ClosureDate, f.AgeDays, f.DaysForClosure,
		})
	}

	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"scanner_findings"},
		[]string{
			"import_id", "source", "source_id", "name", "description", "impact", "solution",
			"assessment_type", "comments", "closure_by_exception", "severity", "status",
			"host_id", "host_raw", "reported_on", "closure_date", "age_days", "days_for_closure",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("copy findings: %w", err)
	}
	if int(copyCount) != len(findings) {
		return fmt.Errorf("copy inserted %d rows, expected %d", copyCount, len(findings))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Extracted-identifier join rows are inserted best-effort in a
	// separate step outside the COPY transaction: COPY doesn't return
	// generated IDs, so we look findings back up by (import_id,
	// source_id) to link join tables. For very large imports this
	// step is also where you'd enqueue a background job instead of
	// doing it inline -- left as an extension point.
	if err := r.linkExtractedIdentifiers(ctx, findings); err != nil {
		return fmt.Errorf("link extracted identifiers: %w", err)
	}

	return nil
}

func (r *FindingRepo) linkExtractedIdentifiers(ctx context.Context, findings []*entity.ScannerFinding) error {
	// Ensure referenced CVE/RHSA rows exist (upsert stubs; full
	// metadata gets backfilled by the RHSA/CVE sync job) before
	// linking, so the FK constraints on finding_cves/finding_rhsas
	// never block an import.
	batch := &pgx.Batch{}
	queued := 0

	for _, f := range findings {
		for _, cve := range f.ExtractedCVEs {
			batch.Queue(`INSERT INTO cves (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, cve)
			queued++
		}
		for _, rhsa := range f.ExtractedRHSAs {
			batch.Queue(`INSERT INTO rhsa_advisories (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, rhsa)
			queued++
		}
	}

	if queued > 0 {
		br := r.pool.SendBatch(ctx, batch)
		for i := 0; i < queued; i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return fmt.Errorf("ensure cve/rhsa stub rows: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	// Linking findings to their extracted identifiers requires
	// knowing the generated finding.ID, which COPY doesn't return.
	// Resolve by (import_id, source_id, name) — good enough for
	// linking purposes; source_id is typically unique per scanner
	// export. Production hardening note: if a scanner omits stable
	// source_id values, switch this resolution step to happen inline
	// during a row-by-row insert path instead of COPY for that
	// scanner's imports.
	if len(findings) == 0 {
		return nil
	}
	importID := findings[0].ImportID

	rows, err := r.pool.Query(ctx, `SELECT id, source_id, name FROM scanner_findings WHERE import_id = $1`, importID)
	if err != nil {
		return fmt.Errorf("resolve inserted finding ids: %w", err)
	}
	defer rows.Close()

	idBySourceIDAndName := make(map[string]string)
	for rows.Next() {
		var id, sourceID, name string
		if err := rows.Scan(&id, &sourceID, &name); err != nil {
			return err
		}
		idBySourceIDAndName[sourceID+"|"+name] = id
	}
	if err := rows.Err(); err != nil {
		return err
	}

	linkBatch := &pgx.Batch{}
	linked := 0
	for _, f := range findings {
		id, ok := idBySourceIDAndName[f.SourceID+"|"+f.Name]
		if !ok {
			continue
		}
		for _, cve := range f.ExtractedCVEs {
			linkBatch.Queue(`INSERT INTO finding_cves (finding_id, cve_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, cve)
			linked++
		}
		for _, rhsa := range f.ExtractedRHSAs {
			linkBatch.Queue(`INSERT INTO finding_rhsas (finding_id, rhsa_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, rhsa)
			linked++
		}
		for _, pkg := range f.ExtractedPackages {
			linkBatch.Queue(`INSERT INTO finding_packages (finding_id, package_name) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, pkg)
			linked++
		}
	}

	if linked > 0 {
		br := r.pool.SendBatch(ctx, linkBatch)
		for i := 0; i < linked; i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return fmt.Errorf("link finding identifiers: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (r *FindingRepo) Get(ctx context.Context, id string) (*entity.ScannerFinding, error) {
	const q = `
		SELECT id, import_id, source, source_id, name, description, impact, solution,
		       assessment_type, comments, closure_by_exception, severity, status,
		       COALESCE(host_id::text, ''), host_raw, reported_on, closure_date,
		       age_days, days_for_closure, remediation_task_id, created_at, updated_at
		FROM scanner_findings WHERE id = $1`

	row := r.pool.QueryRow(ctx, q, id)
	f := &entity.ScannerFinding{}
	var remediationTaskID *string
	var severity, status string
	err := row.Scan(
		&f.ID, &f.ImportID, &f.Source, &f.SourceID, &f.Name, &f.Description, &f.Impact, &f.Solution,
		&f.AssessmentType, &f.Comments, &f.ClosureByException, &severity, &status,
		&f.HostID, &f.HostRaw, &f.ReportedOn, &f.ClosureDate,
		&f.AgeDays, &f.DaysForClosure, &remediationTaskID, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get finding %s: %w", id, err)
	}
	f.Severity = entity.Severity(severity)
	f.Status = entity.FindingStatus(status)
	f.RemediationTaskID = remediationTaskID
	return f, nil
}

// List, UpdateStatus, AttachRemediationTask, and UnresolvedForCorrelation
// follow the same pgx-idiomatic patterns as Get/BulkInsert above.
// Elided here for brevity in this scaffold; each should be filled in
// with server-side pagination (LIMIT/OFFSET or, better, keyset
// pagination on created_at+id for the 100k+ scale target) before
// this repo is considered production-complete.

func (r *FindingRepo) List(ctx context.Context, f repository.FindingFilter) ([]*entity.ScannerFinding, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.Severity != "" {
		where += " AND severity = " + arg(string(f.Severity))
	}
	if f.Status != "" {
		where += " AND status = " + arg(string(f.Status))
	}
	if f.HostID != "" {
		where += " AND host_id = " + arg(f.HostID)
	}
	if f.RHSAID != "" {
		where += fmt.Sprintf(" AND id IN (SELECT finding_id FROM finding_rhsas WHERE rhsa_id = %s)", arg(f.RHSAID))
	}
	if f.CVEID != "" {
		where += fmt.Sprintf(" AND id IN (SELECT finding_id FROM finding_cves WHERE cve_id = %s)", arg(f.CVEID))
	}
	if f.PackageName != "" {
		where += fmt.Sprintf(" AND id IN (SELECT finding_id FROM finding_packages WHERE package_name = %s)", arg(f.PackageName))
	}
	if f.Search != "" {
		s := arg("%" + f.Search + "%")
		where += fmt.Sprintf(" AND (name ILIKE %s OR description ILIKE %s OR host_raw ILIKE %s)", s, s, s)
	}

	page, pageSize := normalizePage(f.Page, f.PageSize)
	offset := (page - 1) * pageSize

	var total int
	countQ := "SELECT count(*) FROM scanner_findings " + where
	if err := r.pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count findings: %w", err)
	}

	listArgs := append(append([]interface{}{}, args...), pageSize, offset)
	listQ := fmt.Sprintf(`
		SELECT id, import_id, source, source_id, name, description, impact, solution,
		       assessment_type, comments, closure_by_exception, severity, status,
		       COALESCE(host_id::text, ''), host_raw, reported_on, closure_date,
		       age_days, days_for_closure, created_at, updated_at
		FROM scanner_findings %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, len(args)+1, len(args)+2)

	rows, err := r.pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var out []*entity.ScannerFinding
	for rows.Next() {
		fnd := &entity.ScannerFinding{}
		var severity, status string
		if err := rows.Scan(
			&fnd.ID, &fnd.ImportID, &fnd.Source, &fnd.SourceID, &fnd.Name, &fnd.Description, &fnd.Impact, &fnd.Solution,
			&fnd.AssessmentType, &fnd.Comments, &fnd.ClosureByException, &severity, &status,
			&fnd.HostID, &fnd.HostRaw, &fnd.ReportedOn, &fnd.ClosureDate,
			&fnd.AgeDays, &fnd.DaysForClosure, &fnd.CreatedAt, &fnd.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		fnd.Severity = entity.Severity(severity)
		fnd.Status = entity.FindingStatus(status)
		out = append(out, fnd)
	}
	return out, total, rows.Err()
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}
	return page, pageSize
}

func (r *FindingRepo) UpdateStatus(ctx context.Context, id string, status entity.FindingStatus) error {
	_, err := r.pool.Exec(ctx, `UPDATE scanner_findings SET status=$1, updated_at=now() WHERE id=$2`, string(status), id)
	if err != nil {
		return fmt.Errorf("update finding status: %w", err)
	}
	return nil
}

func (r *FindingRepo) AttachRemediationTask(ctx context.Context, findingIDs []string, taskID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE scanner_findings SET remediation_task_id=$1, status='pending_verification', updated_at=now() WHERE id = ANY($2)`,
		taskID, findingIDs,
	)
	if err != nil {
		return fmt.Errorf("attach remediation task: %w", err)
	}
	return nil
}

// UnresolvedForCorrelation uses keyset pagination (cursor = last seen
// UUID as text) rather than OFFSET, which stays fast even after
// millions of rows have been scanned by prior correlation passes.
func (r *FindingRepo) UnresolvedForCorrelation(ctx context.Context, batchSize int, cursor string) ([]*entity.ScannerFinding, string, error) {
	q := `
		SELECT id, import_id, source, source_id, name, description, impact, solution,
		       assessment_type, comments, closure_by_exception, severity, status,
		       COALESCE(host_id::text, ''), host_raw, reported_on, closure_date,
		       age_days, days_for_closure, created_at, updated_at
		FROM scanner_findings
		WHERE remediation_task_id IS NULL AND host_id IS NOT NULL`
	args := []interface{}{}
	if cursor != "" {
		q += ` AND id > $1`
		args = append(args, cursor)
	}
	q += fmt.Sprintf(` ORDER BY id ASC LIMIT %d`, batchSize)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("query unresolved findings: %w", err)
	}
	defer rows.Close()

	var out []*entity.ScannerFinding
	var lastID string
	for rows.Next() {
		f := &entity.ScannerFinding{}
		var severity, status string
		if err := rows.Scan(
			&f.ID, &f.ImportID, &f.Source, &f.SourceID, &f.Name, &f.Description, &f.Impact, &f.Solution,
			&f.AssessmentType, &f.Comments, &f.ClosureByException, &severity, &status,
			&f.HostID, &f.HostRaw, &f.ReportedOn, &f.ClosureDate,
			&f.AgeDays, &f.DaysForClosure, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, "", err
		}
		f.Severity = entity.Severity(severity)
		f.Status = entity.FindingStatus(status)

		// ExtractedCVEs/RHSAs/Packages are populated via join-table
		// lookups; omitted here for brevity — join finding_cves/
		// finding_rhsas/finding_packages the same way Get() would,
		// or denormalize onto scanner_findings if this becomes a hot
		// path (100k+ findings per correlation pass).
		out = append(out, f)
		lastID = f.ID
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(out) == batchSize {
		next = lastID
	}
	return out, next, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
