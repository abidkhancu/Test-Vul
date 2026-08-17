package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type RHSARepo struct {
	pool *pgxpool.Pool
}

func NewRHSARepo(pool *pgxpool.Pool) *RHSARepo {
	return &RHSARepo{pool: pool}
}

var _ repository.RHSARepository = (*RHSARepo)(nil)

func (r *RHSARepo) Upsert(ctx context.Context, a *entity.RHSAAdvisory) error {
	const q = `
		INSERT INTO rhsa_advisories (id, synopsis, severity, issued_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET
			synopsis = COALESCE(NULLIF(EXCLUDED.synopsis, ''), rhsa_advisories.synopsis),
			severity = EXCLUDED.severity,
			issued_at = COALESCE(EXCLUDED.issued_at, rhsa_advisories.issued_at)`
	_, err := r.pool.Exec(ctx, q, a.ID, a.Synopsis, string(a.Severity), a.IssuedAt)
	return err
}

func (r *RHSARepo) Get(ctx context.Context, id string) (*entity.RHSAAdvisory, error) {
	const q = `SELECT id, COALESCE(synopsis,''), severity, issued_at, created_at FROM rhsa_advisories WHERE id=$1`
	a := &entity.RHSAAdvisory{}
	var severity string
	if err := r.pool.QueryRow(ctx, q, id).Scan(&a.ID, &a.Synopsis, &severity, &a.IssuedAt, &a.CreatedAt); err != nil {
		return nil, fmt.Errorf("get rhsa %s: %w", id, err)
	}
	a.Severity = entity.Severity(severity)

	cveRows, err := r.pool.Query(ctx, `SELECT cve_id FROM rhsa_cves WHERE rhsa_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer cveRows.Close()
	for cveRows.Next() {
		var cveID string
		if err := cveRows.Scan(&cveID); err != nil {
			return nil, err
		}
		a.CVEIDs = append(a.CVEIDs, cveID)
	}

	pkgRows, err := r.pool.Query(ctx, `SELECT package_name FROM rhsa_packages WHERE rhsa_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer pkgRows.Close()
	for pkgRows.Next() {
		var pkg string
		if err := pkgRows.Scan(&pkg); err != nil {
			return nil, err
		}
		a.PackageNames = append(a.PackageNames, pkg)
	}

	return a, nil
}

func (r *RHSARepo) LinkCVEs(ctx context.Context, rhsaID string, cveIDs []string) error {
	batch := &pgx.Batch{}
	for _, cveID := range cveIDs {
		batch.Queue(`INSERT INTO cves (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, cveID)
		batch.Queue(`INSERT INTO rhsa_cves (rhsa_id, cve_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, rhsaID, cveID)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(cveIDs)*2; i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("link cves to %s: %w", rhsaID, err)
		}
	}
	return nil
}

func (r *RHSARepo) LinkPackages(ctx context.Context, rhsaID string, packageNames []string) error {
	batch := &pgx.Batch{}
	for _, pkg := range packageNames {
		batch.Queue(`INSERT INTO rhsa_packages (rhsa_id, package_name) VALUES ($1,$2) ON CONFLICT DO NOTHING`, rhsaID, pkg)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(packageNames); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("link packages to %s: %w", rhsaID, err)
		}
	}
	return nil
}

// FindCoveringAdvisory looks for a single RHSA that already links to
// every CVE in cveIDs and (if pkg is non-empty) to that package. This
// is the query the correlation engine leans on to prefer one-patch
// remediation over N individual CVE tasks.
func (r *RHSARepo) FindCoveringAdvisory(ctx context.Context, cveIDs []string, packageName, osFamily string) (*entity.RHSAAdvisory, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	const q = `
		SELECT rc.rhsa_id
		FROM rhsa_cves rc
		WHERE rc.cve_id = ANY($1)
		GROUP BY rc.rhsa_id
		HAVING COUNT(DISTINCT rc.cve_id) = $2
		LIMIT 1`
	var rhsaID string
	err := r.pool.QueryRow(ctx, q, cveIDs, len(cveIDs)).Scan(&rhsaID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("find covering advisory: %w", err)
	}

	// osFamily is accepted for future package-repo-channel filtering
	// (e.g. same CVE fixed by different advisories on RHEL8 vs
	// RHEL9); not yet enforced in this query — see TODO.
	_ = osFamily
	_ = packageName

	return r.Get(ctx, rhsaID)
}
