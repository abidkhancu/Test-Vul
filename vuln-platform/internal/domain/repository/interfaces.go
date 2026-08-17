// Package repository defines the outbound ports (interfaces) that the
// domain/usecase layers depend on. Concrete adapters (Postgres, Redis,
// etc.) live in internal/repository/* and are wired in at
// cmd/server/main.go via dependency injection. Nothing in
// internal/domain or internal/usecase may import a concrete driver
// package directly.
package repository

import (
	"context"
	"time"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

type HostRepository interface {
	Create(ctx context.Context, h *entity.Host) error
	Get(ctx context.Context, id string) (*entity.Host, error)
	FindByHostnameOrIP(ctx context.Context, hostnameOrIP string) (*entity.Host, error)
	Upsert(ctx context.Context, h *entity.Host) error
	UpdateStatus(ctx context.Context, id string, status entity.HostStatus) error
	List(ctx context.Context, f HostFilter) ([]*entity.Host, int, error)
}

type HostFilter struct {
	Environment    string
	Status         entity.HostStatus
	Search         string
	Page, PageSize int
}

type CredentialRepository interface {
	Create(ctx context.Context, c *entity.Credential) error
	Get(ctx context.Context, id string) (*entity.Credential, error) // returns ciphertext only; caller must decrypt via crypto service
}

type ImportRepository interface {
	CreateBatch(ctx context.Context, b *entity.ImportBatch) error
	UpdateBatch(ctx context.Context, b *entity.ImportBatch) error
	GetBatch(ctx context.Context, id string) (*entity.ImportBatch, error)
	ListRecent(ctx context.Context, limit int) ([]*entity.ImportBatch, error)
}

type FindingRepository interface {
	// BulkInsert inserts findings in batches for import throughput.
	// Implementations should use COPY or multi-row INSERT rather than
	// row-by-row inserts to sustain 100k+ finding imports.
	BulkInsert(ctx context.Context, findings []*entity.ScannerFinding) error
	Get(ctx context.Context, id string) (*entity.ScannerFinding, error)
	List(ctx context.Context, f FindingFilter) ([]*entity.ScannerFinding, int, error)
	UpdateStatus(ctx context.Context, id string, status entity.FindingStatus) error
	AttachRemediationTask(ctx context.Context, findingIDs []string, taskID string) error

	// UnresolvedForCorrelation streams findings that have not yet been
	// assigned to a remediation task, in pages, for the correlation
	// engine to consume.
	UnresolvedForCorrelation(ctx context.Context, batchSize int, cursor string) ([]*entity.ScannerFinding, string, error)
}

type FindingFilter struct {
	Severity       entity.Severity
	Status         entity.FindingStatus
	HostID         string
	PackageName    string
	RHSAID         string
	CVEID          string
	Search         string
	Page, PageSize int
}

type CVERepository interface {
	Upsert(ctx context.Context, c *entity.CVE) error
	Get(ctx context.Context, id string) (*entity.CVE, error)
	GetMany(ctx context.Context, ids []string) ([]*entity.CVE, error)
}

type RHSARepository interface {
	Upsert(ctx context.Context, r *entity.RHSAAdvisory) error
	Get(ctx context.Context, id string) (*entity.RHSAAdvisory, error)
	LinkCVEs(ctx context.Context, rhsaID string, cveIDs []string) error
	LinkPackages(ctx context.Context, rhsaID string, packageNames []string) error
	// FindCoveringAdvisory returns the RHSA (if any) that covers ALL
	// of the given CVEs for the given package on the given host's OS
	// family. Used by the correlation engine to prefer a single
	// advisory over per-CVE tasks.
	FindCoveringAdvisory(ctx context.Context, cveIDs []string, packageName, osFamily string) (*entity.RHSAAdvisory, error)
}

type RemediationRepository interface {
	Create(ctx context.Context, t *entity.RemediationTask) error
	Get(ctx context.Context, id string) (*entity.RemediationTask, error)
	// FindOpenByHostAndTarget looks for an existing, non-terminal task
	// for the same host + RHSA (or same host + CVE-set when no RHSA
	// is known) so the correlation engine can merge into it instead
	// of creating a duplicate.
	FindOpenByHostAndTarget(ctx context.Context, hostID string, rhsaID *string, cveIDs []string) (*entity.RemediationTask, error)
	Update(ctx context.Context, t *entity.RemediationTask) error
	UpdateStatus(ctx context.Context, id string, status entity.RemediationStatus) error
	List(ctx context.Context, f RemediationFilter) ([]*entity.RemediationTask, int, error)

	Approve(ctx context.Context, id, approvedBy string) error
	Reject(ctx context.Context, id, rejectedBy, reason string) error
}

type RemediationFilter struct {
	Status         entity.RemediationStatus
	Severity       entity.Severity
	HostID         string
	Page, PageSize int
}

type PatchJobRepository interface {
	Create(ctx context.Context, j *entity.PatchJob) error
	Update(ctx context.Context, j *entity.PatchJob) error
	Get(ctx context.Context, id string) (*entity.PatchJob, error)
	ListByTask(ctx context.Context, taskID string) ([]*entity.PatchJob, error)
}

type AuditRepository interface {
	// Write must never block or drop a security-relevant event.
	// Implementations should treat audit-write failure as fatal to
	// the enclosing operation (fail closed) for approval/patch
	// actions, and best-effort for read-only verification actions.
	Write(ctx context.Context, log *entity.AuditLog) error
	Query(ctx context.Context, f AuditFilter) ([]*entity.AuditLog, int, error)
}

type AuditFilter struct {
	Username       string
	Action         string
	HostID         string
	From, To       *time.Time
	Page, PageSize int
}
