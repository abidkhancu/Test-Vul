package patch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	gossh "golang.org/x/crypto/ssh"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/ssh"
)

// Executor runs an approved patch command over SSH and performs
// post-patch verification. It depends on ssh.Verifier for both the
// connection (so patching reuses the exact same jump-host/host-key
// path as verification) and the post-patch re-check (so "did the
// patch actually take" isn't self-reported by the patch command's
// exit code alone).
type Executor struct {
	guard       *Guard
	verifier    *ssh.Verifier
	hosts       repository.HostRepository
	remediation repository.RemediationRepository
	patchJobs   repository.PatchJobRepository
	audit       repository.AuditRepository
	log         zerolog.Logger
}

func NewExecutor(
	guard *Guard,
	verifier *ssh.Verifier,
	hosts repository.HostRepository,
	remediation repository.RemediationRepository,
	patchJobs repository.PatchJobRepository,
	audit repository.AuditRepository,
	log zerolog.Logger,
) *Executor {
	return &Executor{
		guard:       guard,
		verifier:    verifier,
		hosts:       hosts,
		remediation: remediation,
		patchJobs:   patchJobs,
		audit:       audit,
		log:         log.With().Str("component", "patch_executor").Logger(),
	}
}

// Run executes the approved patch for remediationTaskID end to end:
// re-authorize -> build command -> connect -> execute -> record ->
// post-patch verify -> update task status. Every step from
// authorization through completion is audited; a failure to write an
// audit entry for the actual patch command is treated as fatal to the
// operation (fail closed) — see writeAuditFailClosed — unlike
// verification's best-effort audit writes.
func (e *Executor) Run(ctx context.Context, remediationTaskID string) (*entity.PatchJob, error) {
	correlationID := uuid.New().String()

	token, err := e.guard.Authorize(ctx, remediationTaskID)
	if err != nil {
		e.writeAudit(ctx, correlationID, "system", "patch.authorize", nil, nil, nil, "denied", err.Error())
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	patchCmd, err := BuildAdvisoryPatch(token)
	if err != nil {
		e.writeAudit(ctx, correlationID, token.ApprovedBy(), "patch.build_command", &token.hostID, nil, nil, "failure", err.Error())
		return nil, err
	}

	host, err := e.hosts.Get(ctx, token.HostID())
	if err != nil {
		return nil, fmt.Errorf("load host %s: %w", token.HostID(), err)
	}

	job := &entity.PatchJob{
		RemediationTaskID: token.RemediationTaskID(),
		HostID:            token.HostID(),
		RHSAID:            token.RHSAID(),
		ApprovedBy:        token.ApprovedBy(),
		ApprovedAt:        token.approvedAt,
		Command:           patchCmd.String(),
		Status:            entity.PatchJobQueued,
	}
	if err := e.patchJobs.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("create patch job record: %w", err)
	}

	if err := e.remediation.UpdateStatus(ctx, token.RemediationTaskID(), entity.RemStatusPatching); err != nil {
		e.log.Warn().Err(err).Str("task_id", token.RemediationTaskID()).Msg("failed to mark task patching")
	}

	e.executeOnHost(ctx, correlationID, host, job, patchCmd)

	if job.Status == entity.PatchJobSucceeded {
		e.postPatchVerify(ctx, correlationID, host, job)
	} else {
		_ = e.remediation.UpdateStatus(ctx, token.RemediationTaskID(), entity.RemStatusPatchFailed)
	}

	return job, nil
}

func (e *Executor) executeOnHost(ctx context.Context, correlationID string, host *entity.Host, job *entity.PatchJob, cmd PatchCommand) {
	now := time.Now()
	job.StartedAt = &now
	job.Status = entity.PatchJobRunning
	_ = e.patchJobs.Update(ctx, job)

	client, err := e.verifier.Connect(ctx, host)
	if err != nil {
		e.finishFailed(ctx, correlationID, job, fmt.Errorf("connect for patch execution: %w", err))
		return
	}

	session, err := client.NewSession()
	if err != nil {
		e.finishFailed(ctx, correlationID, job, fmt.Errorf("open ssh session for patch execution: %w", err))
		return
	}
	defer session.Close()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	runErr := session.Run(cmd.String())
	duration := time.Since(start)

	completed := time.Now()
	job.CompletedAt = &completed
	job.Stdout = stdout.String()
	job.Stderr = stderr.String()

	exitCode := 0
	result := "success"
	detail := ""
	if runErr != nil {
		result = "failure"
		detail = runErr.Error()
		if exitErr, ok := runErr.(*gossh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			exitCode = -1
		}
		job.Status = entity.PatchJobFailed
	} else {
		job.Status = entity.PatchJobSucceeded
	}
	job.ExitCode = &exitCode

	// Patch execution audit writes are fail-closed: if we can't
	// durably record that this command ran, we treat the whole
	// operation as failed even if the remote command itself
	// succeeded, because an unaudited patch on a production banking
	// host is not an acceptable outcome regardless of technical
	// success.
	execMS := duration.Milliseconds()
	auditErr := e.audit.Write(ctx, &entity.AuditLog{
		Timestamp:       start,
		Username:        job.ApprovedBy,
		Action:          "patch.execute",
		HostID:          &host.ID,
		ExecutedCommand: &job.Command,
		ExitCode:        &exitCode,
		ExecutionTimeMS: &execMS,
		Result:          result,
		Detail:          detail,
		CorrelationID:   correlationID,
	})
	if auditErr != nil {
		e.log.Error().Err(auditErr).Str("job_id", job.ID).Msg("CRITICAL: failed to write audit log for patch execution — marking job failed regardless of remote exit code")
		job.Status = entity.PatchJobFailed
	}

	if err := e.patchJobs.Update(ctx, job); err != nil {
		e.log.Error().Err(err).Str("job_id", job.ID).Msg("failed to persist patch job result")
	}
}

func (e *Executor) finishFailed(ctx context.Context, correlationID string, job *entity.PatchJob, cause error) {
	now := time.Now()
	job.CompletedAt = &now
	job.Status = entity.PatchJobFailed
	job.Stderr = cause.Error()
	_ = e.patchJobs.Update(ctx, job)

	e.writeAudit(ctx, correlationID, job.ApprovedBy, "patch.execute", &job.HostID, &job.Command, nil, "failure", cause.Error())
}

// postPatchVerify re-runs the read-only verification workflow after a
// successful patch, per spec: "Verify installed RHSA, verify package
// version, verify changelog, verify pending advisories... recommend
// scanner rescan, update remediation status." It deliberately reuses
// ssh.Verifier.Verify rather than trusting the patch command's own
// exit code as proof of remediation.
func (e *Executor) postPatchVerify(ctx context.Context, correlationID string, host *entity.Host, job *entity.PatchJob) {
	task, err := e.remediation.Get(ctx, job.RemediationTaskID)
	if err != nil {
		e.log.Error().Err(err).Str("task_id", job.RemediationTaskID).Msg("failed to load task for post-patch verification")
		return
	}

	_ = e.remediation.UpdateStatus(ctx, task.ID, entity.RemStatusPatchVerifying)

	result, err := e.verifier.Verify(ctx, task)
	if err != nil {
		e.log.Error().Err(err).Str("task_id", task.ID).Msg("post-patch verification failed to run")
		return
	}

	passed := result.Outcome == ssh.OutcomeAlreadyInstalled
	job.PostVerifyPassed = &passed
	_ = e.patchJobs.Update(ctx, job)

	if passed {
		_ = e.remediation.UpdateStatus(ctx, task.ID, entity.RemStatusRemediated)
	} else {
		// Patch command exited 0 but post-verification didn't confirm
		// the advisory is now installed — flag for manual follow-up
		// rather than silently declaring success. Common causes:
		// reboot-required kernel update, repo lag, or the advisory
		// covering a package not actually present on this host.
		_ = e.remediation.UpdateStatus(ctx, task.ID, entity.RemStatusPatchFailed)
		e.log.Warn().Str("task_id", task.ID).Str("outcome", string(result.Outcome)).
			Msg("patch command succeeded but post-patch verification did not confirm remediation — needs manual follow-up (possible reboot-required update)")
	}

	e.writeAudit(ctx, correlationID, job.ApprovedBy, "patch.post_verify", &host.ID, nil, nil,
		map[bool]string{true: "success", false: "failure"}[passed],
		fmt.Sprintf("outcome=%s", result.Outcome))
}

func (e *Executor) writeAudit(ctx context.Context, correlationID, username, action string, hostID *string, command *string, exitCode *int, result, detail string) {
	log := &entity.AuditLog{
		Timestamp:       time.Now(),
		Username:        username,
		Action:          action,
		HostID:          hostID,
		ExecutedCommand: command,
		ExitCode:        exitCode,
		Result:          result,
		Detail:          detail,
		CorrelationID:   correlationID,
	}
	if err := e.audit.Write(ctx, log); err != nil {
		e.log.Error().Err(err).Str("action", action).Msg("failed to write audit log entry")
	}
}
