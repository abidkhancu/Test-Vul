package reporting

import (
	"bytes"
	"encoding/csv"
	"fmt"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

// Table is the shared intermediate representation both the CSV and
// XLSX writers render from — one aggregation step, two renderers,
// rather than duplicating "how do I turn a ScannerFinding into a row"
// logic per output format.
type Table struct {
	Title   string
	Headers []string
	Rows    [][]string
}

func WriteCSV(t Table) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if err := w.Write(t.Headers); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}
	for _, row := range t.Rows {
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("write csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}
	return buf.Bytes(), nil
}

// --- Table builders: one per report type, each pulling from the
// domain entities already fetched by Generator, never issuing new
// queries themselves. Keeping these pure functions (entity slice in,
// Table out) means the same builder feeds both WriteCSV and
// WriteXLSX with zero duplication.

func FindingsTable(findings []*entity.ScannerFinding) Table {
	t := Table{
		Title:   "Scanner Findings",
		Headers: []string{"ID", "Source", "Host", "Name", "Severity", "Status", "Reported On", "Extracted CVEs", "Extracted RHSAs"},
	}
	for _, f := range findings {
		reported := ""
		if f.ReportedOn != nil {
			reported = f.ReportedOn.Format("2006-01-02")
		}
		t.Rows = append(t.Rows, []string{
			f.ID, f.Source, f.HostRaw, f.Name, string(f.Severity), string(f.Status), reported,
			joinOrDash(f.ExtractedCVEs), joinOrDash(f.ExtractedRHSAs),
		})
	}
	return t
}

func HostsTable(hosts []*entity.Host) Table {
	t := Table{
		Title:   "Managed Hosts",
		Headers: []string{"ID", "Hostname", "IP Address", "Environment", "OS Family", "Status", "Last Seen"},
	}
	for _, h := range hosts {
		lastSeen := ""
		if h.LastSeenAt != nil {
			lastSeen = h.LastSeenAt.Format("2006-01-02 15:04")
		}
		t.Rows = append(t.Rows, []string{
			h.ID, h.Hostname, h.IPAddress, h.Environment, h.OSFamily, string(h.Status), lastSeen,
		})
	}
	return t
}

func RemediationTable(tasks []*entity.RemediationTask) Table {
	t := Table{
		Title:   "Remediation Tasks",
		Headers: []string{"ID", "Host ID", "RHSA", "Severity", "Status", "Approved By", "Last Verified"},
	}
	for _, task := range tasks {
		rhsa := "-"
		if task.RHSAID != nil {
			rhsa = *task.RHSAID
		}
		approvedBy := "-"
		if task.ApprovedBy != nil {
			approvedBy = *task.ApprovedBy
		}
		lastVerified := ""
		if task.LastVerifiedAt != nil {
			lastVerified = task.LastVerifiedAt.Format("2006-01-02 15:04")
		}
		t.Rows = append(t.Rows, []string{
			task.ID, task.HostID, rhsa, string(task.Severity), string(task.Status), approvedBy, lastVerified,
		})
	}
	return t
}

func PatchJobsTable(jobs []*entity.PatchJob) Table {
	t := Table{
		Title:   "Patch Jobs",
		Headers: []string{"ID", "Host ID", "RHSA", "Approved By", "Status", "Exit Code", "Post-Verify Passed", "Completed At"},
	}
	for _, j := range jobs {
		exitCode := "-"
		if j.ExitCode != nil {
			exitCode = fmt.Sprintf("%d", *j.ExitCode)
		}
		verified := "-"
		if j.PostVerifyPassed != nil {
			verified = fmt.Sprintf("%v", *j.PostVerifyPassed)
		}
		completed := ""
		if j.CompletedAt != nil {
			completed = j.CompletedAt.Format("2006-01-02 15:04")
		}
		t.Rows = append(t.Rows, []string{
			j.ID, j.HostID, j.RHSAID, j.ApprovedBy, string(j.Status), exitCode, verified, completed,
		})
	}
	return t
}

func AuditTable(logs []*entity.AuditLog) Table {
	t := Table{
		Title:   "Audit Log",
		Headers: []string{"Timestamp", "Username", "Action", "Host ID", "Command", "Exit Code", "Result", "Detail"},
	}
	for _, l := range logs {
		hostID := "-"
		if l.HostID != nil {
			hostID = *l.HostID
		}
		cmd := "-"
		if l.ExecutedCommand != nil {
			cmd = *l.ExecutedCommand
		}
		exitCode := "-"
		if l.ExitCode != nil {
			exitCode = fmt.Sprintf("%d", *l.ExitCode)
		}
		t.Rows = append(t.Rows, []string{
			l.Timestamp.Format("2006-01-02 15:04:05"), l.Username, l.Action, hostID, cmd, exitCode, l.Result, l.Detail,
		})
	}
	return t
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	out := items[0]
	for _, s := range items[1:] {
		out += "; " + s
	}
	return out
}
