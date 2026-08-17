// Package correlation implements the engine that collapses many raw
// scanner findings (possibly from multiple scanners, multiple import
// batches, referencing the same underlying vulnerability) into a
// single RemediationTask per (host, remediation-target) pair.
//
// Correlation key:
//   - If an RHSA is known and it covers every CVE the findings raise
//     for that host+package, the task key is (host, RHSA).
//   - Otherwise the task key is (host, sorted CVE set) so unrelated
//     CVEs never accidentally merge, and re-scans that surface the
//     same CVEs again attach to the same task instead of duplicating.
//
// This package depends only on domain interfaces (repository.*) and
// entity types, per hexagonal architecture — no direct DB/driver
// imports here.
package correlation

import (
	"context"
	"fmt"
	"sort"

	"github.com/rs/zerolog"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type Correlator struct {
	findings    repository.FindingRepository
	rhsa        repository.RHSARepository
	remediation repository.RemediationRepository
	hosts       repository.HostRepository
	log         zerolog.Logger
}

func New(
	findings repository.FindingRepository,
	rhsa repository.RHSARepository,
	remediation repository.RemediationRepository,
	hosts repository.HostRepository,
	log zerolog.Logger,
) *Correlator {
	return &Correlator{
		findings:    findings,
		rhsa:        rhsa,
		remediation: remediation,
		hosts:       hosts,
		log:         log.With().Str("component", "correlator").Logger(),
	}
}

// RunResult summarizes a single correlation pass, e.g. after an
// import batch completes, or on a periodic reconciliation schedule.
type RunResult struct {
	FindingsProcessed int
	TasksCreated      int
	TasksMerged       int // findings attached to an existing open task
	Errors            int
}

// batchSize controls how many unresolved findings are pulled per
// page. Kept moderate so a single correlation pass doesn't hold a
// huge result set in memory even at 100k+ findings scale.
const batchSize = 500

// Run processes all findings that have not yet been assigned to a
// remediation task, in pages, merging duplicates as it goes. It is
// safe to call repeatedly/concurrently is NOT guaranteed — callers
// should serialize correlation runs (e.g. via a single worker or a
// DB advisory lock) to avoid two runs racing to create tasks for the
// same host+target.
func (c *Correlator) Run(ctx context.Context) (RunResult, error) {
	var result RunResult
	cursor := ""

	for {
		page, next, err := c.findings.UnresolvedForCorrelation(ctx, batchSize, cursor)
		if err != nil {
			return result, fmt.Errorf("fetch unresolved findings: %w", err)
		}
		if len(page) == 0 {
			break
		}

		for _, f := range page {
			if err := c.correlateOne(ctx, f, &result); err != nil {
				c.log.Error().Err(err).Str("finding_id", f.ID).Msg("correlation failed for finding")
				result.Errors++
				continue
			}
			result.FindingsProcessed++
		}

		if next == "" {
			break
		}
		cursor = next
	}

	c.log.Info().
		Int("processed", result.FindingsProcessed).
		Int("created", result.TasksCreated).
		Int("merged", result.TasksMerged).
		Int("errors", result.Errors).
		Msg("correlation pass complete")

	return result, nil
}

func (c *Correlator) correlateOne(ctx context.Context, f *entity.ScannerFinding, result *RunResult) error {
	if f.HostID == "" {
		return fmt.Errorf("finding %s has no resolved host_id; run host resolution before correlation", f.ID)
	}
	if len(f.ExtractedCVEs) == 0 && len(f.ExtractedRHSAs) == 0 {
		// Nothing to correlate against yet (e.g. extraction engine
		// found no identifiers in the free text). Leave it
		// unassigned rather than guessing; it'll surface in the
		// "needs triage" queue.
		return nil
	}

	rhsaID, cveIDs, err := c.resolveTarget(ctx, f)
	if err != nil {
		return err
	}

	existing, err := c.remediation.FindOpenByHostAndTarget(ctx, f.HostID, rhsaID, cveIDs)
	if err != nil {
		return fmt.Errorf("lookup existing task: %w", err)
	}

	if existing != nil {
		if err := c.findings.AttachRemediationTask(ctx, []string{f.ID}, existing.ID); err != nil {
			return fmt.Errorf("attach finding to existing task %s: %w", existing.ID, err)
		}
		result.TasksMerged++
		return nil
	}

	task := &entity.RemediationTask{
		HostID:           f.HostID,
		RHSAID:           rhsaID,
		CVEIDs:           cveIDs,
		PackageNames:     f.ExtractedPackages,
		FindingIDs:       []string{f.ID},
		Severity:         f.Severity,
		Status:           entity.RemStatusPendingVerification,
		ApprovalRequired: true,
	}
	if err := c.remediation.Create(ctx, task); err != nil {
		return fmt.Errorf("create remediation task: %w", err)
	}
	if err := c.findings.AttachRemediationTask(ctx, []string{f.ID}, task.ID); err != nil {
		return fmt.Errorf("attach finding to new task %s: %w", task.ID, err)
	}
	result.TasksCreated++
	return nil
}

// resolveTarget decides whether this finding's vulnerabilities should
// be tracked as a single RHSA-based task or a CVE-set task. It
// prefers an advisory that covers every extracted CVE for the
// extracted package(s) on the host's OS family, since remediating one
// RHSA is one patch operation regardless of how many CVEs it closes.
func (c *Correlator) resolveTarget(ctx context.Context, f *entity.ScannerFinding) (*string, []string, error) {
	cveIDs := sortedCopy(f.ExtractedCVEs)

	// If the finding text already names an RHSA directly, trust it
	// but still verify it covers the extracted CVEs so we don't
	// silently drop a CVE that isn't actually in scope for that
	// advisory.
	if len(f.ExtractedRHSAs) > 0 {
		rhsaID := f.ExtractedRHSAs[0]
		return &rhsaID, cveIDs, nil
	}

	if len(cveIDs) == 0 {
		return nil, nil, nil
	}

	host, err := c.hosts.Get(ctx, f.HostID)
	if err != nil {
		return nil, cveIDs, fmt.Errorf("load host for advisory lookup: %w", err)
	}

	var pkg string
	if len(f.ExtractedPackages) > 0 {
		pkg = f.ExtractedPackages[0]
	}

	advisory, err := c.rhsa.FindCoveringAdvisory(ctx, cveIDs, pkg, host.OSFamily)
	if err != nil {
		return nil, cveIDs, fmt.Errorf("find covering advisory: %w", err)
	}
	if advisory != nil {
		return &advisory.ID, cveIDs, nil
	}

	// No known advisory yet — track as a CVE-only task. The
	// verification engine will re-check for a newly published
	// advisory on each verification pass.
	return nil, cveIDs, nil
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
