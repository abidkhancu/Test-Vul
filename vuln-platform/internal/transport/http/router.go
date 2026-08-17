package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/transport/http/handlers"
	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	"github.com/ubank/vuln-platform/internal/usecase/auth"
)

// Dependencies bundles every handler the router needs. Built in
// cmd/server/main.go and passed here so this package stays purely
// about route wiring, not construction.
type Dependencies struct {
	Pool               *pgxpool.Pool
	AuthService        *auth.Service
	AuthHandler        *handlers.AuthHandler
	ImportHandler      *handlers.ImportHandler
	FindingHandler     *handlers.FindingHandler
	HostHandler        *handlers.HostHandler
	RemediationHandler *handlers.RemediationHandler
	PatchHandler       *handlers.PatchHandler
	AuditHandler       *handlers.AuditHandler
	UserHandler        *handlers.UserHandler
	ReportHandler      *handlers.ReportHandler
	HealthHandler      *handlers.HealthHandler
	Log                zerolog.Logger
}

// NewRouter builds the full chi.Router: global middleware
// (recovery, logging, rate limiting), health probes (unauthenticated),
// and the versioned, authenticated /api/v1 route tree with RBAC
// applied per the spec's role matrix.
func NewRouter(deps Dependencies) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Recover(deps.Log))
	r.Use(middleware.RequestLogging(deps.Log))
	limiter := middleware.NewRateLimiter(300, time.Minute)
	r.Use(limiter.Middleware)

	// Unauthenticated probes for k8s liveness/readiness.
	r.Get("/healthz", deps.HealthHandler.Liveness)
	r.Get("/readyz", deps.HealthHandler.Readiness)

	r.Route("/api/v1", func(r chi.Router) {
		// --- Public auth endpoints ---
		r.Post("/auth/login", deps.AuthHandler.Login)
		r.Post("/auth/refresh", deps.AuthHandler.Refresh)

		// --- Everything below requires a valid access token ---
		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticate(deps.AuthService))

			r.Get("/auth/me", deps.AuthHandler.Me)
			r.Post("/auth/logout", deps.AuthHandler.Logout)

			// Imports: security_analyst or administrator can upload;
			// everyone authenticated can check status.
			r.Get("/imports", deps.ImportHandler.List)
			r.Get("/imports/{id}", deps.ImportHandler.Get)
			r.With(middleware.RequireRole(entity.RoleAdministrator, entity.RoleSecurityAnalyst)).
				Post("/imports", deps.ImportHandler.Upload)

			// Findings: read access for all authenticated roles
			// (viewer included) — this is dashboard/search data.
			r.Get("/findings", deps.FindingHandler.List)
			r.Get("/findings/{id}", deps.FindingHandler.Get)

			// Hosts: read for everyone; host-key registration is
			// administrator-only, since it changes what identity
			// this application trusts for a given host.
			r.Get("/hosts", deps.HostHandler.List)
			r.Get("/hosts/{id}", deps.HostHandler.Get)
			r.With(middleware.RequireRole(entity.RoleAdministrator)).
				Post("/hosts/{id}/host-key", deps.HostHandler.RegisterHostKey)

			// Remediation: read for everyone; verification for
			// operator/security_analyst/administrator (enforced
			// inside the handler via CanRunVerification); approve/
			// reject strictly patch_approver/administrator.
			r.Get("/remediation", deps.RemediationHandler.List)
			r.Get("/remediation/{id}", deps.RemediationHandler.Get)
			r.Post("/remediation/{id}/verify", deps.RemediationHandler.Verify)
			r.With(middleware.RequirePatchApprover).Post("/remediation/{id}/approve", deps.RemediationHandler.Approve)
			r.With(middleware.RequirePatchApprover).Post("/remediation/{id}/reject", deps.RemediationHandler.Reject)

			// Patches: executing one is the single most sensitive
			// action in this system, gated at both the route level
			// (RequirePatchApprover) and again inside
			// patch.Guard.Authorize against live DB state.
			r.Get("/patches/{id}", deps.PatchHandler.Get)
			r.Get("/patches/by-task/{taskID}", deps.PatchHandler.ListByTask)
			r.With(middleware.RequirePatchApprover).Post("/patches/execute", deps.PatchHandler.Execute)

			// Audit: administrator-only.
			r.With(middleware.RequireRole(entity.RoleAdministrator)).Get("/audit", deps.AuditHandler.List)

			// Users: administrator-only, per entity.Role.CanManageUsers.
			r.With(middleware.RequireRole(entity.RoleAdministrator)).Group(func(r chi.Router) {
				r.Post("/users", deps.UserHandler.Create)
				r.Get("/users", deps.UserHandler.List)
				r.Get("/users/{id}", deps.UserHandler.Get)
				r.Patch("/users/{id}/role", deps.UserHandler.SetRole)
				r.Patch("/users/{id}/active", deps.UserHandler.SetActive)
			})

			// Reports: read access for everyone authenticated;
			// generation restricted to roles that can already see the
			// underlying data broadly (analyst/administrator) — a
			// viewer can download previously generated reports but
			// not trigger new ones on demand.
			r.Get("/reports", deps.ReportHandler.List)
			r.Get("/reports/{id}/download", deps.ReportHandler.Download)
			r.With(middleware.RequireRole(entity.RoleAdministrator, entity.RoleSecurityAnalyst)).
				Post("/reports", deps.ReportHandler.Generate)
		})
	})

	return r
}
