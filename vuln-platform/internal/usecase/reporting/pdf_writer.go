package reporting

import (
	"bytes"
	"fmt"

	"github.com/jung-kurt/gofpdf"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

// WriteExecutiveSummaryPDF renders the one-page, leadership-facing
// summary: headline counts and a severity breakdown. This is the
// spec's "Executive Summary" report — intentionally short and
// numbers-first rather than a dump of every finding (that's what the
// Technical/Host/Package/etc CSV and XLSX exports are for).
func WriteExecutiveSummaryPDF(stats *ExecutiveSummaryStats) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 20)
	pdf.CellFormat(0, 12, "Vulnerability Management — Executive Summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(0, 6, "Generated report — figures reflect current database state at time of generation", "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(6)

	section := func(title string) {
		pdf.SetFont("Arial", "B", 13)
		pdf.SetFillColor(31, 41, 55)
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(0, 8, "  "+title, "", 1, "L", true, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(2)
	}

	kv := func(label string, value int) {
		pdf.SetFont("Arial", "", 11)
		pdf.CellFormat(90, 7, label, "", 0, "L", false, 0, "")
		pdf.SetFont("Arial", "B", 11)
		pdf.CellFormat(0, 7, fmt.Sprintf("%d", value), "", 1, "L", false, 0, "")
	}

	section("Findings Overview")
	kv("Total findings imported", stats.TotalFindings)
	kv("Open findings", stats.OpenFindings)
	kv("Closed findings", stats.ClosedFindings)
	pdf.Ln(4)

	section("Findings by Severity")
	kv("Critical", stats.BySeverity[entity.SeverityCritical])
	kv("High", stats.BySeverity[entity.SeverityHigh])
	kv("Medium", stats.BySeverity[entity.SeverityMedium])
	kv("Low", stats.BySeverity[entity.SeverityLow])
	pdf.Ln(4)

	section("Fleet & Remediation")
	kv("Managed hosts", stats.TotalHosts)
	kv("Remediation tasks (total)", stats.TotalRemediation)
	kv("Pending approval", stats.PendingApproval)
	kv("Approved (awaiting/queued for patch)", stats.Approved)
	kv("Remediated", stats.Remediated)
	kv("Patch failed (needs follow-up)", stats.PatchFailed)
	kv("SSH failed (host unreachable)", stats.SSHFailed)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("render executive summary pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteTablePDF renders any Table (findings, hosts, remediation
// tasks, patch jobs, audit entries) as a paginated PDF with a repeated
// header row. Used for the spec's Technical/Host/Package/RHSA/CVE/
// Verification/Patch/Audit report types when PDF format is requested.
func WriteTablePDF(t Table) ([]byte, error) {
	pdf := gofpdf.New("L", "mm", "A4", "") // landscape: these tables tend to be wide
	pdf.SetMargins(12, 15, 12)
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(0, 10, t.Title, "", 1, "L", false, 0, "")
	pdf.Ln(2)

	if len(t.Headers) == 0 {
		pdf.SetFont("Arial", "", 11)
		pdf.CellFormat(0, 8, "(no data)", "", 1, "L", false, 0, "")
		var buf bytes.Buffer
		if err := pdf.Output(&buf); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	pageWidth, _ := pdf.GetPageSize()
	marginL, _, marginR, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginL - marginR
	colWidth := usableWidth / float64(len(t.Headers))

	drawHeader := func() {
		pdf.SetFont("Arial", "B", 9)
		pdf.SetFillColor(31, 41, 55)
		pdf.SetTextColor(255, 255, 255)
		for _, h := range t.Headers {
			pdf.CellFormat(colWidth, 7, truncate(h, colWidth), "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Arial", "", 8)
	}

	drawHeader()
	_, pageHeight := pdf.GetPageSize()
	_, _, _, marginB := pdf.GetMargins()

	for _, row := range t.Rows {
		if pdf.GetY() > pageHeight-marginB-10 {
			pdf.AddPage()
			drawHeader()
		}
		for i, cell := range row {
			if i >= len(t.Headers) {
				break
			}
			pdf.CellFormat(colWidth, 6, truncate(cell, colWidth), "1", 0, "L", false, 0, "")
		}
		pdf.Ln(-1)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("render table pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// truncate keeps cell text from overflowing the fixed column width
// (gofpdf doesn't wrap CellFormat text automatically). Rough
// character-per-mm heuristic rather than exact text measurement —
// good enough for a generated report, not meant to be pixel-perfect.
func truncate(s string, widthMM float64) string {
	maxChars := int(widthMM / 1.8)
	if maxChars < 3 {
		maxChars = 3
	}
	if len(s) <= maxChars {
		return s
	}
	if maxChars <= 3 {
		return s[:maxChars]
	}
	return s[:maxChars-3] + "..."
}
