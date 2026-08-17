package entity

import "time"

// RemediationStatus tracks a correlated remediation task from
// discovery through post-patch verification. This is the primary
// workflow state machine of the platform.
//
//	pending_verification -> verifying -> verified_vulnerable -> pending_approval
//	    -> approved -> patch_scheduled -> patching -> patch_verifying
//	    -> remediated  (terminal, success)
//
//	verifying -> already_remediated (terminal, no action needed)
//	verifying -> ssh_failed / not_applicable (terminal, needs manual follow-up)
//	patching -> patch_failed (terminal, needs manual follow-up / retry)
type RemediationStatus string

const (
	RemStatusPendingVerification RemediationStatus = "pending_verification"
	RemStatusVerifying           RemediationStatus = "verifying"
	RemStatusVerifiedVulnerable  RemediationStatus = "verified_vulnerable"
	RemStatusAlreadyRemediated   RemediationStatus = "already_remediated"
	RemStatusNotApplicable       RemediationStatus = "not_applicable"
	RemStatusSSHFailed           RemediationStatus = "ssh_failed"
	RemStatusPendingApproval     RemediationStatus = "pending_approval"
	RemStatusApproved            RemediationStatus = "approved"
	RemStatusPatchScheduled      RemediationStatus = "patch_scheduled"
	RemStatusPatching            RemediationStatus = "patching"
	RemStatusPatchVerifying      RemediationStatus = "patch_verifying"
	RemStatusRemediated          RemediationStatus = "remediated"
	RemStatusPatchFailed         RemediationStatus = "patch_failed"
	RemStatusRejected            RemediationStatus = "rejected"
)

// IsTerminal reports whether a remediation task has reached a state
// that requires no further automated action.
func (s RemediationStatus) IsTerminal() bool {
	switch s {
	case RemStatusRemediated, RemStatusAlreadyRemediated, RemStatusNotApplicable, RemStatusRejected:
		return true
	default:
		return false
	}
}

// RemediationTask is the correlation engine's output: one task per
// unique (host, RHSA-or-CVE-set) combination, deduplicated across
// however many raw scanner findings reported it.
type RemediationTask struct {
	ID     string `json:"id" db:"id"`
	HostID string `json:"host_id" db:"host_id"`

	// Primary remediation target. Prefer an RHSA if one covers all
	// affected CVEs/packages; fall back to a CVE-only task if no
	// advisory is known yet (e.g. embargoed CVE).
	RHSAID *string `json:"rhsa_id,omitempty" db:"rhsa_id"`

	CVEIDs       []string `json:"cve_ids" db:"-"`       // via remediation_task_cves join table
	PackageNames []string `json:"package_names" db:"-"` // via remediation_task_packages join table
	FindingIDs   []string `json:"finding_ids" db:"-"`   // raw findings collapsed into this task

	Severity Severity          `json:"severity" db:"severity"` // highest severity among constituent findings
	Status   RemediationStatus `json:"status" db:"status"`

	// Verification results (read-only SSH checks).
	LastVerifiedAt    *time.Time `json:"last_verified_at,omitempty" db:"last_verified_at"`
	VerificationNotes string     `json:"verification_notes,omitempty" db:"verification_notes"`

	// Approval.
	ApprovalRequired bool       `json:"approval_required" db:"approval_required"`
	ApprovedBy       *string    `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty" db:"approved_at"`
	RejectedReason   *string    `json:"rejected_reason,omitempty" db:"rejected_reason"`

	// Scheduling.
	ScheduledFor *time.Time `json:"scheduled_for,omitempty" db:"scheduled_for"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// PatchJob is a single execution attempt of an approved remediation
// task. Every PatchJob must reference an ApprovedBy actor and an
// approved RemediationTask; the patch executor rejects any job that
// doesn't satisfy that invariant (see usecase/patch.Executor).
type PatchJobStatus string

const (
	PatchJobQueued    PatchJobStatus = "queued"
	PatchJobRunning   PatchJobStatus = "running"
	PatchJobSucceeded PatchJobStatus = "succeeded"
	PatchJobFailed    PatchJobStatus = "failed"
	PatchJobCancelled PatchJobStatus = "cancelled"
)

type PatchJob struct {
	ID                  string         `json:"id" db:"id"`
	RemediationTaskID   string         `json:"remediation_task_id" db:"remediation_task_id"`
	HostID              string         `json:"host_id" db:"host_id"`
	RHSAID              string         `json:"rhsa_id" db:"rhsa_id"`
	ApprovedBy          string         `json:"approved_by" db:"approved_by"`
	ApprovedAt          time.Time      `json:"approved_at" db:"approved_at"`
	Command             string         `json:"command" db:"command"` // exact command executed, e.g. "dnf update --advisory=RHSA-2025:7937"
	Status              PatchJobStatus `json:"status" db:"status"`
	ExitCode            *int           `json:"exit_code,omitempty" db:"exit_code"`
	Stdout              string         `json:"stdout,omitempty" db:"stdout"`
	Stderr              string         `json:"stderr,omitempty" db:"stderr"`
	StartedAt           *time.Time     `json:"started_at,omitempty" db:"started_at"`
	CompletedAt         *time.Time     `json:"completed_at,omitempty" db:"completed_at"`
	PostVerifyPassed    *bool          `json:"post_verify_passed,omitempty" db:"post_verify_passed"`
	MaintenanceWindowID *string        `json:"maintenance_window_id,omitempty" db:"maintenance_window_id"`
	CreatedAt           time.Time      `json:"created_at" db:"created_at"`
}

// AuditLog is an append-only record of every security-relevant action
// taken by the platform or its users. Nothing that touches a host,
// credential, or approval decision should happen without a
// corresponding AuditLog entry written in the same transaction (or,
// where that's not possible, immediately before/after with a
// correlation ID).
type AuditLog struct {
	ID              string    `json:"id" db:"id"`
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`
	Username        string    `json:"username" db:"username"`
	Action          string    `json:"action" db:"action"` // e.g. "ssh.verify", "patch.approve", "patch.execute"
	HostID          *string   `json:"host_id,omitempty" db:"host_id"`
	ExecutedCommand *string   `json:"executed_command,omitempty" db:"executed_command"`
	ExitCode        *int      `json:"exit_code,omitempty" db:"exit_code"`
	ExecutionTimeMS *int64    `json:"execution_time_ms,omitempty" db:"execution_time_ms"`
	Result          string    `json:"result" db:"result"` // success | failure | denied
	Detail          string    `json:"detail,omitempty" db:"detail"`
	CorrelationID   string    `json:"correlation_id" db:"correlation_id"`
}
