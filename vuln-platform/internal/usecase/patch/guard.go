// Package patch implements the approval-gated patch execution engine.
// It is deliberately isolated from usecase/ssh's read-only command
// builder — this is the only package in the codebase permitted to
// construct a package-modifying command, and it can only do so after
// producing an ApprovalToken, which can only be minted by Guard.Authorize
// after re-reading the RemediationTask's approval state from the
// database at execution time (not trusting an in-memory status that
// might be stale).
package patch

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

var rhsaIDPattern = regexp.MustCompile(`^RHSA-\d{4}:\d{3,6}$`)

// ApprovalToken proves a specific RemediationTask has been approved,
// by a specific human, as of a specific time, for a specific RHSA. It
// has no exported constructor — the only way to get one is through
// Guard.Authorize, which re-checks the database. Executor.Run (in
// executor.go) refuses to run without one.
type ApprovalToken struct {
	remediationTaskID string
	hostID            string
	rhsaID            string
	approvedBy        string
	approvedAt        time.Time
	fullSystemUpdate  bool // always false unless ExplicitFullSystemUpdate was used — see AuthorizeFullSystemUpdate
}

func (t ApprovalToken) RemediationTaskID() string { return t.remediationTaskID }
func (t ApprovalToken) HostID() string            { return t.hostID }
func (t ApprovalToken) RHSAID() string            { return t.rhsaID }
func (t ApprovalToken) ApprovedBy() string        { return t.approvedBy }

// Guard is the single authorization choke point for patch execution.
// Nothing else in the codebase should read remediation_tasks.status
// == 'approved' and treat that alone as sufficient to run a patch —
// every execution path must go through Guard.Authorize immediately
// before running, so a task that was approved and then later
// rejected/re-opened (e.g. a re-scan found the fix already applied by
// someone else) can never be patched on stale state.
type Guard struct {
	remediation           repository.RemediationRepository
	allowFullSystemUpdate bool // wired from config.Safety.AllowFullSystemUpdate
}

func NewGuard(remediation repository.RemediationRepository, allowFullSystemUpdate bool) *Guard {
	return &Guard{remediation: remediation, allowFullSystemUpdate: allowFullSystemUpdate}
}

// Authorize re-reads the task from the database and, only if it is in
// the 'approved' state with a non-empty ApprovedBy, mints an
// ApprovalToken scoped to exactly that task's RHSA. Every other state
// — pending_approval, rejected, already remediated, or anything else
// — returns an error and no token.
func (g *Guard) Authorize(ctx context.Context, remediationTaskID string) (ApprovalToken, error) {
	task, err := g.remediation.Get(ctx, remediationTaskID)
	if err != nil {
		return ApprovalToken{}, fmt.Errorf("load remediation task %s: %w", remediationTaskID, err)
	}

	if task.Status != entity.RemStatusApproved {
		return ApprovalToken{}, fmt.Errorf("remediation task %s is not approved (current status: %s); refusing to authorize patch execution", remediationTaskID, task.Status)
	}
	if task.ApprovedBy == nil || *task.ApprovedBy == "" {
		return ApprovalToken{}, fmt.Errorf("remediation task %s has status=approved but no approved_by set; refusing to authorize (data integrity issue, do not patch)", remediationTaskID)
	}
	if task.RHSAID == nil || *task.RHSAID == "" {
		return ApprovalToken{}, fmt.Errorf("remediation task %s has no associated RHSA; CVE-only tasks cannot be patched automatically — requires manual remediation or a published advisory first", remediationTaskID)
	}
	if !rhsaIDPattern.MatchString(*task.RHSAID) {
		return ApprovalToken{}, fmt.Errorf("remediation task %s has malformed RHSA id %q; refusing to authorize", remediationTaskID, *task.RHSAID)
	}
	if task.ScheduledFor != nil && time.Now().Before(*task.ScheduledFor) {
		return ApprovalToken{}, fmt.Errorf("remediation task %s is scheduled for %s (maintenance window not yet open); refusing to execute early", remediationTaskID, task.ScheduledFor.Format(time.RFC3339))
	}

	approvedAt := time.Now()
	if task.ApprovedAt != nil {
		approvedAt = *task.ApprovedAt
	}

	return ApprovalToken{
		remediationTaskID: task.ID,
		hostID:            task.HostID,
		rhsaID:            *task.RHSAID,
		approvedBy:        *task.ApprovedBy,
		approvedAt:        approvedAt,
	}, nil
}

// AuthorizeFullSystemUpdate is a deliberately separate, more
// restrictive path for the spec's "Full System Update" option (the
// only context in which `dnf update -y` is ever permitted). It:
//   - requires the same approved-task checks as Authorize
//   - additionally requires the operator config to have
//     Safety.AllowFullSystemUpdate=true (an explicit deployment-level
//     opt-in, not just a per-request flag)
//   - additionally requires explicitConfirm=true, meaning the calling
//     HTTP handler must have received an unambiguous "yes, full
//     system update, not just this advisory" confirmation from the
//     approver — never inferred, never defaulted.
func (g *Guard) AuthorizeFullSystemUpdate(ctx context.Context, remediationTaskID string, explicitConfirm bool) (ApprovalToken, error) {
	if !g.allowFullSystemUpdate {
		return ApprovalToken{}, fmt.Errorf("full system update is disabled at the deployment level (safety.allow_full_system_update=false); this is not overridable per-request")
	}
	if !explicitConfirm {
		return ApprovalToken{}, fmt.Errorf("full system update requires explicit confirmation; refusing an implicit/default request")
	}

	token, err := g.Authorize(ctx, remediationTaskID)
	if err != nil {
		return ApprovalToken{}, err
	}
	token.fullSystemUpdate = true
	return token, nil
}
