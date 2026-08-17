package entity

import "time"

// FindingStatus tracks a raw scanner finding through the remediation
// lifecycle. This is distinct from RemediationTask status: many
// findings collapse into one remediation task via the correlation
// engine.
type FindingStatus string

const (
	FindingStatusOpen                FindingStatus = "open"
	FindingStatusPendingVerification FindingStatus = "pending_verification"
	FindingStatusVerified            FindingStatus = "verified" // confirmed vulnerable
	FindingStatusAlreadyRemediated   FindingStatus = "already_remediated"
	FindingStatusClosed              FindingStatus = "closed"
	FindingStatusFalsePositive       FindingStatus = "false_positive"
)

// ScannerFinding is the normalized representation of a single row
// imported from a CSV/XLSX vulnerability report. One finding maps to
// one (host, vulnerability) pair as reported by one scanner run.
type ScannerFinding struct {
	ID       string `json:"id" db:"id"`
	ImportID string `json:"import_id" db:"import_id"`

	// Raw/source fields, preserved as reported.
	Source             string `json:"source" db:"source"`       // scanner name, e.g. "Qualys", "Nessus"
	SourceID           string `json:"source_id" db:"source_id"` // scanner's own finding ID
	Name               string `json:"name" db:"name"`
	Description        string `json:"description" db:"description"`
	Impact             string `json:"impact" db:"impact"`
	Solution           string `json:"solution" db:"solution"`
	AssessmentType     string `json:"assessment_type" db:"assessment_type"`
	Comments           string `json:"comments" db:"comments"`
	ClosureByException bool   `json:"closure_by_exception" db:"closure_by_exception"`

	// Normalized/derived fields.
	Severity Severity      `json:"severity" db:"severity"`
	Status   FindingStatus `json:"status" db:"status"`
	HostID   string        `json:"host_id" db:"host_id"`
	HostRaw  string        `json:"host_raw" db:"host_raw"` // original "Host/Application" value

	ReportedOn     *time.Time `json:"reported_on,omitempty" db:"reported_on"`
	ClosureDate    *time.Time `json:"closure_date,omitempty" db:"closure_date"`
	AgeDays        *int       `json:"age_days,omitempty" db:"age_days"`
	DaysForClosure *int       `json:"days_for_closure,omitempty" db:"days_for_closure"`

	// Extracted references populated by the extraction engine.
	ExtractedCVEs     []string `json:"extracted_cves,omitempty" db:"-"`
	ExtractedRHSAs    []string `json:"extracted_rhsas,omitempty" db:"-"`
	ExtractedPackages []string `json:"extracted_packages,omitempty" db:"-"`

	RemediationTaskID *string `json:"remediation_task_id,omitempty" db:"remediation_task_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ImportBatch tracks a single CSV/XLSX file import job.
type ImportStatus string

const (
	ImportStatusPending    ImportStatus = "pending"
	ImportStatusProcessing ImportStatus = "processing"
	ImportStatusCompleted  ImportStatus = "completed"
	ImportStatusFailed     ImportStatus = "failed"
	ImportStatusPartial    ImportStatus = "partial" // completed with row-level errors
)

type ImportBatch struct {
	ID            string       `json:"id" db:"id"`
	Filename      string       `json:"filename" db:"filename"`
	FileType      string       `json:"file_type" db:"file_type"` // csv | xlsx
	Status        ImportStatus `json:"status" db:"status"`
	TotalRows     int          `json:"total_rows" db:"total_rows"`
	ProcessedRows int          `json:"processed_rows" db:"processed_rows"`
	FailedRows    int          `json:"failed_rows" db:"failed_rows"`
	ErrorSummary  string       `json:"error_summary,omitempty" db:"error_summary"`
	UploadedBy    string       `json:"uploaded_by" db:"uploaded_by"`
	StartedAt     *time.Time   `json:"started_at,omitempty" db:"started_at"`
	CompletedAt   *time.Time   `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt     time.Time    `json:"created_at" db:"created_at"`
}
