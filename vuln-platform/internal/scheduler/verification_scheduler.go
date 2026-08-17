// Package scheduler runs periodic background passes that aren't
// triggered by a specific HTTP request: verification sweeps over
// tasks awaiting a read-only SSH check, alongside the correlation
// engine's own periodic reconciliation (see internal/worker and
// cmd/server/main.go's runPeriodicCorrelation).
package scheduler

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/ssh"
)

// VerificationScheduler periodically pulls tasks sitting in
// pending_verification and runs the read-only workflow against them,
// so newly-correlated remediation tasks don't wait indefinitely for
// someone to click "verify" in the UI. It intentionally does nothing
// with patch execution — that stays 100% human-triggered via the
// approval workflow; there is no scheduled/automatic patching path in
// this codebase.
type VerificationScheduler struct {
	remediation repository.RemediationRepository
	verifier    *ssh.Verifier
	interval    time.Duration
	batchSize   int
	log         zerolog.Logger
}

func NewVerificationScheduler(
	remediation repository.RemediationRepository,
	verifier *ssh.Verifier,
	interval time.Duration,
	batchSize int,
	log zerolog.Logger,
) *VerificationScheduler {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &VerificationScheduler{
		remediation: remediation,
		verifier:    verifier,
		interval:    interval,
		batchSize:   batchSize,
		log:         log.With().Str("component", "verification_scheduler").Logger(),
	}
}

// Run blocks until ctx is cancelled, running one sweep immediately and
// then on each tick of the configured interval.
func (s *VerificationScheduler) Run(ctx context.Context) {
	s.sweep(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

func (s *VerificationScheduler) sweep(ctx context.Context) {
	tasks, _, err := s.remediation.List(ctx, repository.RemediationFilter{
		Status:   entity.RemStatusPendingVerification,
		Page:     1,
		PageSize: s.batchSize,
	})
	if err != nil {
		// RemediationRepo.List is currently a stub in this scaffold
		// (see repository/postgres/remediation_repo.go) — this will
		// error until that's implemented with a real WHERE/pagination
		// builder. Logged rather than fatal so the rest of the
		// scheduler loop keeps running once that lands.
		s.log.Error().Err(err).Msg("failed to list pending_verification tasks (is RemediationRepo.List implemented yet?)")
		return
	}

	s.log.Info().Int("count", len(tasks)).Msg("starting verification sweep")
	for _, task := range tasks {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := s.verifier.Verify(ctx, task); err != nil {
			s.log.Error().Err(err).Str("task_id", task.ID).Msg("scheduled verification failed")
		}
	}
}
