package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

type HealthHandler struct {
	pool *pgxpool.Pool
}

func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

// GET /healthz — liveness: is the process up at all. Never checks
// dependencies, so a slow/down database doesn't get the process
// killed and restarted by an orchestrator when a restart wouldn't
// help (use /readyz for that distinction).
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	vhttp.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /readyz — readiness: can this instance actually serve traffic.
// Checked against the DB pool since every meaningful endpoint needs
// it; an orchestrator should stop routing traffic here (not restart
// the pod) when this fails.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := h.pool.Ping(ctx); err != nil {
		vhttp.WriteError(w, http.StatusServiceUnavailable, "database not reachable")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
