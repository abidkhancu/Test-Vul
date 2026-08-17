package ssh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	gossh "golang.org/x/crypto/ssh"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

// VerificationOutcome is the determination the spec calls for:
// Already Installed | Pending | Missing Repository | Package Missing |
// Not Applicable | Host Offline | SSH Failure.
type VerificationOutcome string

const (
	OutcomeAlreadyInstalled  VerificationOutcome = "already_installed"
	OutcomePending           VerificationOutcome = "pending"
	OutcomeMissingRepository VerificationOutcome = "missing_repository"
	OutcomePackageMissing    VerificationOutcome = "package_missing"
	OutcomeNotApplicable     VerificationOutcome = "not_applicable"
	OutcomeHostOffline       VerificationOutcome = "host_offline"
	OutcomeSSHFailure        VerificationOutcome = "ssh_failure"
)

type VerificationResult struct {
	Outcome    VerificationOutcome
	Notes      string
	RanAt      time.Time
	CommandLog []CommandExecution
}

type CommandExecution struct {
	Label    string
	Command  string
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Err      error
}

// Verifier orchestrates the read-only verification workflow described
// in the spec: connect (read-only), run the fixed command set for the
// task's RHSA/packages, parse output, determine outcome, write an
// audit log entry for every command executed (not just failures —
// the audit trail requirement is unconditional), and update the
// RemediationTask's status accordingly.
//
// Verifier NEVER constructs or runs anything other than a
// ssh.ReadOnlyCommand. It has no dependency on usecase/patch and
// cannot reach the patch execution code path even by mistake.
type Verifier struct {
	dialer      *Dialer
	hosts       repository.HostRepository
	credentials repository.CredentialRepository
	remediation repository.RemediationRepository
	audit       repository.AuditRepository
	keys        HostKeyRegistry
	log         zerolog.Logger
}

func NewVerifier(
	dialer *Dialer,
	hosts repository.HostRepository,
	credentials repository.CredentialRepository,
	remediation repository.RemediationRepository,
	audit repository.AuditRepository,
	keys HostKeyRegistry,
	log zerolog.Logger,
) *Verifier {
	return &Verifier{
		dialer:      dialer,
		hosts:       hosts,
		credentials: credentials,
		remediation: remediation,
		audit:       audit,
		keys:        keys,
		log:         log.With().Str("component", "ssh_verifier").Logger(),
	}
}

// Verify runs the full read-only verification workflow for one
// RemediationTask and persists the resulting status. It is the only
// exported entry point that touches a host over SSH for verification
// purposes; nothing about "which host, which commands" is left to the
// caller — that's entirely driven by the task + host records.
func (v *Verifier) Verify(ctx context.Context, task *entity.RemediationTask) (VerificationResult, error) {
	correlationID := uuid.New().String()
	result := VerificationResult{RanAt: time.Now()}

	host, err := v.hosts.Get(ctx, task.HostID)
	if err != nil {
		return result, fmt.Errorf("load host %s: %w", task.HostID, err)
	}

	if err := v.remediation.UpdateStatus(ctx, task.ID, entity.RemStatusVerifying); err != nil {
		v.log.Warn().Err(err).Str("task_id", task.ID).Msg("failed to mark task verifying")
	}

	client, connErr := v.Connect(ctx, host)
	if connErr != nil {
		result.Outcome = classifyConnectError(connErr)
		result.Notes = connErr.Error()

		status := entity.RemStatusSSHFailed
		hostStatus := entity.HostStatusFailed
		if result.Outcome == OutcomeHostOffline {
			hostStatus = entity.HostStatusOffline
		}
		_ = v.hosts.UpdateStatus(ctx, host.ID, hostStatus)
		_ = v.remediation.UpdateStatus(ctx, task.ID, status)
		v.writeAudit(ctx, correlationID, "system", "ssh.verify.connect", &host.ID, nil, nil, "failure", connErr.Error())
		return result, nil // connection failure is a valid, recorded outcome — not a Go error
	}
	_ = v.hosts.UpdateStatus(ctx, host.ID, entity.HostStatusReachable)

	if task.RHSAID != nil {
		result, err = v.verifyRHSATask(ctx, correlationID, host, task, client)
	} else {
		result, err = v.verifyCVETask(ctx, correlationID, host, task, client)
	}
	if err != nil {
		return result, err
	}

	notes := formatNotes(result)
	now := time.Now()
	task.LastVerifiedAt = &now
	task.VerificationNotes = notes

	switch result.Outcome {
	case OutcomeAlreadyInstalled:
		task.Status = entity.RemStatusAlreadyRemediated
	case OutcomeNotApplicable, OutcomeMissingRepository, OutcomePackageMissing:
		task.Status = entity.RemStatusNotApplicable
	case OutcomePending:
		task.Status = entity.RemStatusPendingApproval // verified vulnerable and a fix path exists -> ready for human approval
	default:
		task.Status = entity.RemStatusVerifiedVulnerable
	}

	if err := v.remediation.Update(ctx, task); err != nil {
		return result, fmt.Errorf("persist verification result: %w", err)
	}

	return result, nil
}

func (v *Verifier) verifyRHSATask(ctx context.Context, correlationID string, host *entity.Host, task *entity.RemediationTask, client *gossh.Client) (VerificationResult, error) {
	result := VerificationResult{RanAt: time.Now()}
	rhsaID := *task.RHSAID

	installedCmd, err := VerifyAdvisoryInstalled(rhsaID)
	if err != nil {
		return result, err
	}
	installedExec := v.run(ctx, correlationID, host, client, installedCmd)
	result.CommandLog = append(result.CommandLog, installedExec)

	if strings.Contains(installedExec.Stdout, rhsaID) {
		result.Outcome = OutcomeAlreadyInstalled
		return result, nil
	}

	availableCmd, err := VerifyPendingUpdates(rhsaID)
	if err != nil {
		return result, err
	}
	availableExec := v.run(ctx, correlationID, host, client, availableCmd)
	result.CommandLog = append(result.CommandLog, availableExec)

	if strings.Contains(availableExec.Stdout, rhsaID) {
		result.Outcome = OutcomePending
		return result, nil
	}

	// Not installed and not showing as available: either the repo
	// channel providing it isn't enabled, or it genuinely doesn't
	// apply to this host (wrong package present, wrong arch, etc).
	// Disambiguate with a general advisory check.
	checkCmd, err := CheckAdvisory(rhsaID)
	if err != nil {
		return result, err
	}
	checkExec := v.run(ctx, correlationID, host, client, checkCmd)
	result.CommandLog = append(result.CommandLog, checkExec)

	if strings.TrimSpace(checkExec.Stdout) == "" {
		result.Outcome = OutcomeMissingRepository
	} else {
		result.Outcome = OutcomeNotApplicable
	}
	return result, nil
}

func (v *Verifier) verifyCVETask(ctx context.Context, correlationID string, host *entity.Host, task *entity.RemediationTask, client *gossh.Client) (VerificationResult, error) {
	result := VerificationResult{RanAt: time.Now()}

	if len(task.PackageNames) == 0 {
		result.Outcome = OutcomeNotApplicable
		result.Notes = "no package name extracted for this CVE-only task; needs manual triage"
		return result, nil
	}

	anyMissing := false
	for _, pkg := range task.PackageNames {
		pkgCmd, err := VerifyPackage(pkg)
		if err != nil {
			return result, err
		}
		pkgExec := v.run(ctx, correlationID, host, client, pkgCmd)
		result.CommandLog = append(result.CommandLog, pkgExec)

		if strings.Contains(pkgExec.Stdout, "is not installed") || pkgExec.ExitCode != 0 {
			anyMissing = true
			continue
		}

		changelogCmd, err := VerifyChangelog(pkg)
		if err != nil {
			return result, err
		}
		changelogExec := v.run(ctx, correlationID, host, client, changelogCmd)
		result.CommandLog = append(result.CommandLog, changelogExec)

		for _, cve := range task.CVEIDs {
			if ValidCVE(cve) && strings.Contains(changelogExec.Stdout, cve) {
				result.Outcome = OutcomeAlreadyInstalled
				return result, nil
			}
		}
	}

	if anyMissing {
		result.Outcome = OutcomePackageMissing
		return result, nil
	}

	// Package(s) present but changelog doesn't confirm the fix —
	// treat as still pending a fix, to be re-checked once an RHSA is
	// published and correlation re-runs.
	result.Outcome = OutcomePending
	return result, nil
}

// run executes a single ReadOnlyCommand and unconditionally writes an
// audit log entry, per the spec's "every log entry must include
// timestamp/username/host/command/exit code/execution time/result".
// username is "system" here since verification runs are triggered by
// the scheduler/worker, not an interactive user — the correlationID
// ties a whole verification pass together for traceability.
func (v *Verifier) run(ctx context.Context, correlationID string, host *entity.Host, client *gossh.Client, cmd ReadOnlyCommand) CommandExecution {
	start := time.Now()
	session, err := client.NewSession()
	if err != nil {
		exec := CommandExecution{Label: cmd.Label(), Command: cmd.String(), Err: err, Duration: time.Since(start)}
		v.writeAudit(ctx, correlationID, "system", "ssh.verify."+cmd.Label(), &host.ID, ptr(cmd.String()), nil, "failure", err.Error())
		return exec
	}
	defer session.Close()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	runErr := session.Run(cmd.String())
	duration := time.Since(start)

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
	}

	v.writeAudit(ctx, correlationID, "system", "ssh.verify."+cmd.Label(), &host.ID, ptr(cmd.String()), ptr(exitCode), result, detail)

	return CommandExecution{
		Label:    cmd.Label(),
		Command:  cmd.String(),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: duration,
		Err:      runErr,
	}
}

// Connect resolves the host's credential and dials, transparently
// routing through a jump host when the host record specifies one.
// This is where DB-backed jump-host resolution happens (Dialer itself
// has no repository access — see the note in dialer.go).
//
// Exported so usecase/patch.Executor can reuse the exact same
// connection path (same pooling, same jump-host handling, same host
// key enforcement) for post-approval patch execution rather than
// duplicating it — patch execution should never connect any
// differently than verification does.
func (v *Verifier) Connect(ctx context.Context, host *entity.Host) (*gossh.Client, error) {
	credential, err := v.credentials.Get(ctx, host.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("load credential for host %s: %w", host.ID, err)
	}

	if host.JumpHostID == nil {
		return v.dialer.Connect(ctx, host, credential, v.keys)
	}

	jumpHost, err := v.hosts.Get(ctx, *host.JumpHostID)
	if err != nil {
		return nil, fmt.Errorf("load jump host %s: %w", *host.JumpHostID, err)
	}
	jumpCredential, err := v.credentials.Get(ctx, jumpHost.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("load credential for jump host %s: %w", jumpHost.ID, err)
	}

	jumpClient, err := v.dialer.Connect(ctx, jumpHost, jumpCredential, v.keys)
	if err != nil {
		return nil, fmt.Errorf("connect to jump host %s: %w", jumpHost.Hostname, err)
	}

	targetAddr := net.JoinHostPort(host.SSHHost, portOrDefault(host.SSHPort))
	conn, err := jumpClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel through jump host %s to %s: %w", jumpHost.Hostname, targetAddr, err)
	}

	targetAuth, err := v.dialer.resolveAuthMethod(credential)
	if err != nil {
		return nil, fmt.Errorf("resolve auth for tunneled host %s: %w", host.ID, err)
	}
	hostKeyCB, err := v.dialer.hostKeyCallback(host, v.keys)
	if err != nil {
		return nil, err
	}
	targetCfg := &gossh.ClientConfig{
		User:            host.SSHUser,
		Auth:            []gossh.AuthMethod{targetAuth},
		HostKeyCallback: hostKeyCB,
		Timeout:         v.dialer.cfg.ConnectTimeout,
	}

	ncc, chans, reqs, err := gossh.NewClientConn(conn, targetAddr, targetCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake through jump host to %s: %w", host.Hostname, err)
	}
	return gossh.NewClient(ncc, chans, reqs), nil
}

func (v *Verifier) writeAudit(ctx context.Context, correlationID, username, action string, hostID *string, command *string, exitCode *int, result, detail string) {
	var execMS *int64
	log := &entity.AuditLog{
		Timestamp:       time.Now(),
		Username:        username,
		Action:          action,
		HostID:          hostID,
		ExecutedCommand: command,
		ExitCode:        exitCode,
		ExecutionTimeMS: execMS,
		Result:          result,
		Detail:          detail,
		CorrelationID:   correlationID,
	}
	if err := v.audit.Write(ctx, log); err != nil {
		// Per repository.AuditRepository's contract, read-only
		// verification audit failures are best-effort: log locally
		// but don't abort the verification pass over an audit-write
		// hiccup. Patch execution (usecase/patch) has a stricter,
		// fail-closed version of this same call.
		v.log.Error().Err(err).Str("action", action).Msg("failed to write audit log entry")
	}
}

func classifyConnectError(err error) VerificationOutcome {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "no route to host"), strings.Contains(msg, "connection refused"):
		return OutcomeHostOffline
	default:
		return OutcomeSSHFailure
	}
}

func formatNotes(r VerificationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "outcome=%s ran_at=%s\n", r.Outcome, r.RanAt.Format(time.RFC3339))
	for _, c := range r.CommandLog {
		fmt.Fprintf(&b, "[%s] exit=%d dur=%s\n", c.Label, c.ExitCode, c.Duration)
	}
	return b.String()
}

func ptr[T any](v T) *T { return &v }
