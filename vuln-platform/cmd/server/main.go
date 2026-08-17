// Command server is the entrypoint for the Vulnerability Management
// Platform API. It loads configuration, establishes the Postgres pool,
// wires the hexagonal-architecture layers together (repositories ->
// usecases -> transport), starts background workers (import processing,
// correlation reconciliation, verification sweeps), serves the REST
// API, and shuts down gracefully on SIGINT/SIGTERM.
//
// Remaining slices not covered here: the React/Next.js frontend and
// Kubernetes/Helm/CI-CD — see README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ubank/vuln-platform/internal/config"
	vcrypto "github.com/ubank/vuln-platform/internal/crypto"
	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/repository/postgres"
	"github.com/ubank/vuln-platform/internal/scheduler"
	vhttp "github.com/ubank/vuln-platform/internal/transport/http"
	"github.com/ubank/vuln-platform/internal/transport/http/handlers"
	"github.com/ubank/vuln-platform/internal/usecase/auth"
	"github.com/ubank/vuln-platform/internal/usecase/correlation"
	"github.com/ubank/vuln-platform/internal/usecase/extraction"
	"github.com/ubank/vuln-platform/internal/usecase/importer"
	"github.com/ubank/vuln-platform/internal/usecase/patch"
	"github.com/ubank/vuln-platform/internal/usecase/reporting"
	"github.com/ubank/vuln-platform/internal/usecase/ssh"
	"github.com/ubank/vuln-platform/internal/worker"
	"github.com/ubank/vuln-platform/pkg/logger"

	"github.com/rs/zerolog"
)

func main() {
	cfg, err := config.Load(os.Getenv("VULN_CONFIG_FILE"))
	if err != nil {
		panic("load config: " + err.Error())
	}

	log := logger.New(cfg.Env, os.Getenv("VULN_LOG_LEVEL"))
	log.Info().Str("env", cfg.Env).Msg("starting vulnerability management platform")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()
	log.Info().Msg("database connection pool established")

	// --- Repositories (adapters) ---
	hostRepo := postgres.NewHostRepo(pool)
	findingRepo := postgres.NewFindingRepo(pool)
	rhsaRepo := postgres.NewRHSARepo(pool)
	remediationRepo := postgres.NewRemediationRepo(pool)
	importRepo := postgres.NewImportRepo(pool)
	credentialRepo := postgres.NewCredentialRepo(pool)
	auditRepo := postgres.NewAuditRepo(pool)
	patchJobRepo := postgres.NewPatchJobRepo(pool)
	hostKeyRegistry := postgres.NewHostKeyRegistry(pool)
	reportRepo := postgres.NewReportRepo(pool)

	// --- Usecases (domain logic) ---
	extractor := extraction.New()
	csvImporter := importer.NewCSVImporter(findingRepo, importRepo, extractor, log)
	xlsxImporter := importer.NewXLSXImporter(findingRepo, importRepo, extractor, log)
	correlator := correlation.New(findingRepo, rhsaRepo, remediationRepo, hostRepo, log)

	// --- Credential encryption ---
	if cfg.Env == "prod" && len(cfg.Auth.CredentialEncryptionKey) != 32 {
		log.Fatal().Msg("auth.credential_encryption_key must be exactly 32 bytes in prod (validated again here defensively)")
	}
	keyBytes := []byte(cfg.Auth.CredentialEncryptionKey)
	if len(keyBytes) != 32 {
		// Dev-only fallback so the scaffold runs without a key
		// configured; NEVER do this in prod — config.validate()
		// already refuses to start in prod without a real 32-byte key.
		keyBytes = make([]byte, 32)
		log.Warn().Msg("no 32-byte auth.credential_encryption_key configured; using an all-zero dev key — DO NOT use this outside local development")
	}
	keyProvider, err := vcrypto.NewStaticKeyProvider("default", keyBytes)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init credential key provider")
	}
	credentialCipher := vcrypto.NewCredentialCipher(keyProvider)

	// --- SSH verification engine ---
	dialer := ssh.NewDialer(ssh.DialerConfig{
		ConnectTimeout:     cfg.SSH.ConnectTimeout,
		CommandTimeout:     cfg.SSH.CommandTimeout,
		MaxRetries:         cfg.SSH.MaxRetries,
		StrictHostKeyCheck: cfg.SSH.StrictHostKeyCheck,
		MaxConcurrent:      cfg.SSH.MaxConcurrent,
	}, credentialCipher)
	verifier := ssh.NewVerifier(dialer, hostRepo, credentialRepo, remediationRepo, auditRepo, hostKeyRegistry, log)

	// --- Patch approval + execution engine ---
	patchGuard := patch.NewGuard(remediationRepo, cfg.Safety.AllowFullSystemUpdate)
	patchExecutor := patch.NewExecutor(patchGuard, verifier, hostRepo, remediationRepo, patchJobRepo, auditRepo, log)

	// --- Reporting engine ---
	reportGenerator := reporting.NewGenerator(
		findingRepo, hostRepo, remediationRepo, patchJobRepo, auditRepo, reportRepo,
		os.TempDir()+"/vuln-platform-reports",
	)

	// --- Auth (JWT + bcrypt) ---
	userRepo := postgres.NewUserRepo(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepo(pool)
	jwtSigningKey := []byte(cfg.Auth.JWTSigningKey)
	if len(jwtSigningKey) == 0 {
		jwtSigningKey = []byte("dev-only-insecure-signing-key-do-not-use-in-prod")
		log.Warn().Msg("no auth.jwt_signing_key configured; using an insecure dev key — config.validate() prevents this in prod")
	}
	authSvc := auth.NewService(userRepo, refreshTokenRepo, jwtSigningKey, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)

	if err := seedInitialAdmin(ctx, userRepo, log); err != nil {
		log.Error().Err(err).Msg("failed to seed initial admin user")
	}

	// --- Background worker pool ---
	importPool := worker.NewPool(
		cfg.Import.WorkerConcurrency,
		cfg.Import.QueueDepth,
		importRepo,
		csvImporter,
		xlsxImporter,
		correlator,
		log,
	)

	// --- Periodic correlation reconciliation ---
	// Catches any findings that failed to correlate inline (e.g. host
	// resolution lagged an import) without requiring a fresh upload.
	go runPeriodicCorrelation(ctx, correlator, log)

	// --- Periodic verification sweep ---
	// Picks up remediation tasks sitting in pending_verification
	// (newly correlated, not yet checked over SSH) without requiring
	// someone to click "verify" in the UI for every one.
	verificationScheduler := scheduler.NewVerificationScheduler(remediationRepo, verifier, 5*time.Minute, 100, log)
	go verificationScheduler.Run(ctx)

	// --- HTTP transport ---
	router := vhttp.NewRouter(vhttp.Dependencies{
		Pool:               pool,
		AuthService:        authSvc,
		AuthHandler:        handlers.NewAuthHandler(authSvc),
		ImportHandler:      handlers.NewImportHandler(importRepo, importPool, os.TempDir()+"/vuln-platform-uploads", cfg.Import.MaxFileSizeMB),
		FindingHandler:     handlers.NewFindingHandler(findingRepo),
		HostHandler:        handlers.NewHostHandler(hostRepo, hostKeyRegistry, auditRepo),
		RemediationHandler: handlers.NewRemediationHandler(remediationRepo, verifier),
		PatchHandler:       handlers.NewPatchHandler(patchExecutor, patchJobRepo),
		AuditHandler:       handlers.NewAuditHandler(auditRepo),
		UserHandler:        handlers.NewUserHandler(userRepo),
		ReportHandler:      handlers.NewReportHandler(reportGenerator, reportRepo),
		HealthHandler:      handlers.NewHealthHandler(pool),
		Log:                log,
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:      router,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
	}

	go func() {
		log.Info().Int("port", cfg.HTTP.Port).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP server failed")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutdown signal received, draining connections")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server did not shut down cleanly within timeout")
	}
	log.Info().Msg("shutdown complete")
}

// seedInitialAdmin creates a default administrator account on first
// boot if no users exist yet, so the platform is usable immediately
// after a fresh deploy rather than requiring direct DB access to
// create the first account. Credentials come from environment
// variables (never hardcoded) and the operator is expected to change
// the password immediately after first login. This is a convenience
// for initial setup, not a long-term account management story — build
// a proper "create user" admin flow (POST /api/v1/users, RBAC-gated
// to administrator) as part of the next auth-related slice.
func seedInitialAdmin(ctx context.Context, users repository.UserRepository, log zerolog.Logger) error {
	_, total, err := users.List(ctx, 1, 1)
	if err != nil {
		return fmt.Errorf("check existing users: %w", err)
	}
	if total > 0 {
		return nil // already bootstrapped
	}

	username := os.Getenv("VULN_SEED_ADMIN_USERNAME")
	email := os.Getenv("VULN_SEED_ADMIN_EMAIL")
	password := os.Getenv("VULN_SEED_ADMIN_PASSWORD")
	if username == "" || email == "" || password == "" {
		log.Warn().Msg("no users exist and VULN_SEED_ADMIN_USERNAME/EMAIL/PASSWORD are not all set — skipping admin seed; you will need to insert the first user directly")
		return nil
	}
	if len(password) < 12 {
		return fmt.Errorf("VULN_SEED_ADMIN_PASSWORD must be at least 12 characters")
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash seed admin password: %w", err)
	}

	admin := &entity.User{
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		Role:         entity.RoleAdministrator,
		IsActive:     true,
	}
	if err := users.Create(ctx, admin); err != nil {
		return fmt.Errorf("create seed admin: %w", err)
	}
	log.Info().Str("username", username).Msg("seeded initial administrator account — change this password immediately after first login")
	return nil
}

// runPeriodicCorrelation runs a correlation pass on a fixed interval
// as a safety net alongside the post-import correlation trigger in
// the worker pool. In production, replace the fixed ticker with
// cobra+cron scheduling (per the spec's "cron" dependency) if you
// need maintenance-window-aware or configurable scheduling.
func runPeriodicCorrelation(ctx context.Context, c *correlation.Correlator, log zerolog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := c.Run(ctx); err != nil {
				log.Error().Err(err).Msg("periodic correlation pass failed")
			}
		}
	}
}
