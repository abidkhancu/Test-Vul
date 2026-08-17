package entity

import "time"

type ReportType string

const (
	ReportExecutiveSummary ReportType = "executive_summary"
	ReportTechnical        ReportType = "technical"
	ReportHost             ReportType = "host"
	ReportPackage          ReportType = "package"
	ReportRHSA             ReportType = "rhsa"
	ReportCVE              ReportType = "cve"
	ReportVerification     ReportType = "verification"
	ReportPatch            ReportType = "patch"
	ReportAudit            ReportType = "audit"
)

type ReportFormat string

const (
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatXLSX ReportFormat = "xlsx"
)

// Report is the metadata record for a generated report artifact. The
// artifact bytes themselves are written to StoragePath (local disk in
// this scaffold; swap for S3/object storage in production) rather
// than stored in Postgres.
type Report struct {
	ID          string       `json:"id" db:"id"`
	ReportType  ReportType   `json:"report_type" db:"report_type"`
	Format      ReportFormat `json:"format" db:"format"`
	StoragePath string       `json:"storage_path" db:"storage_path"`
	GeneratedBy string       `json:"generated_by" db:"generated_by"`
	FiltersJSON string       `json:"filters_json,omitempty" db:"filters_json"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
}
