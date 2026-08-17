// Package reporting implements the reporting engine: aggregating data
// through the existing repository ports (no new queries bypass the
// domain layer) and rendering it as CSV, XLSX, or PDF.
package reporting

import (
	"context"
	"fmt"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

// ExecutiveSummaryStats is the aggregate view for the one-page
// leadership-facing report: counts by severity and by remediation
// stage. Computed by paging through repository.List calls with
// per-severity filters rather than a bespoke SQL aggregate query, so
// the reporting engine never needs direct DB access — it only talks
// to the same domain/repository interfaces every other usecase does.
// For very large datasets, replace this with a dedicated aggregate
// query (e.g. `SELECT severity, status, count(*) ... GROUP BY`) once
// report generation needs to run faster than "page through
// everything" allows.
type ExecutiveSummaryStats struct {
	TotalFindings    int
	OpenFindings     int
	ClosedFindings   int
	BySeverity       map[entity.Severity]int
	TotalHosts       int
	TotalRemediation int
	PendingApproval  int
	Approved         int
	Remediated       int
	PatchFailed      int
	SSHFailed        int
}

type StatsCollector struct {
	findings    repository.FindingRepository
	hosts       repository.HostRepository
	remediation repository.RemediationRepository
}

func NewStatsCollector(findings repository.FindingRepository, hosts repository.HostRepository, remediation repository.RemediationRepository) *StatsCollector {
	return &StatsCollector{findings: findings, hosts: hosts, remediation: remediation}
}

func (s *StatsCollector) ExecutiveSummary(ctx context.Context) (*ExecutiveSummaryStats, error) {
	stats := &ExecutiveSummaryStats{BySeverity: make(map[entity.Severity]int)}

	_, total, err := s.findings.List(ctx, repository.FindingFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	stats.TotalFindings = total

	_, closed, err := s.findings.List(ctx, repository.FindingFilter{Status: entity.FindingStatusClosed, Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("count closed findings: %w", err)
	}
	stats.ClosedFindings = closed
	stats.OpenFindings = stats.TotalFindings - stats.ClosedFindings

	for _, sev := range []entity.Severity{entity.SeverityCritical, entity.SeverityHigh, entity.SeverityMedium, entity.SeverityLow} {
		_, count, err := s.findings.List(ctx, repository.FindingFilter{Severity: sev, Page: 1, PageSize: 1})
		if err != nil {
			return nil, fmt.Errorf("count %s findings: %w", sev, err)
		}
		stats.BySeverity[sev] = count
	}

	_, hostTotal, err := s.hosts.List(ctx, repository.HostFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("count hosts: %w", err)
	}
	stats.TotalHosts = hostTotal

	_, remTotal, err := s.remediation.List(ctx, repository.RemediationFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("count remediation tasks: %w", err)
	}
	stats.TotalRemediation = remTotal

	statusCounts := map[entity.RemediationStatus]*int{
		entity.RemStatusPendingApproval: &stats.PendingApproval,
		entity.RemStatusApproved:        &stats.Approved,
		entity.RemStatusRemediated:      &stats.Remediated,
		entity.RemStatusPatchFailed:     &stats.PatchFailed,
		entity.RemStatusSSHFailed:       &stats.SSHFailed,
	}
	for status, dest := range statusCounts {
		_, count, err := s.remediation.List(ctx, repository.RemediationFilter{Status: status, Page: 1, PageSize: 1})
		if err != nil {
			return nil, fmt.Errorf("count %s tasks: %w", status, err)
		}
		*dest = count
	}

	return stats, nil
}
