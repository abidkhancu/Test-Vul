package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/repository/postgres"
	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

type HostHandler struct {
	hosts    repository.HostRepository
	hostKeys *postgres.HostKeyRegistry
	audit    repository.AuditRepository
}

func NewHostHandler(hosts repository.HostRepository, hostKeys *postgres.HostKeyRegistry, audit repository.AuditRepository) *HostHandler {
	return &HostHandler{hosts: hosts, hostKeys: hostKeys, audit: audit}
}

// GET /api/v1/hosts?environment=&status=&search=&page=&page_size=
func (h *HostHandler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	f := repository.HostFilter{
		Environment: r.URL.Query().Get("environment"),
		Status:      entity.HostStatus(r.URL.Query().Get("status")),
		Search:      r.URL.Query().Get("search"),
		Page:        page,
		PageSize:    pageSize,
	}
	hosts, total, err := h.hosts.List(r.Context(), f)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]interface{}{"hosts": hosts, "total": total})
}

// GET /api/v1/hosts/{id}
func (h *HostHandler) Get(w http.ResponseWriter, r *http.Request) {
	host, err := h.hosts.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, host)
}

type registerHostKeyRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// POST /api/v1/hosts/{id}/host-key
//
// Deliberately administrator-only (enforced by the router, not here)
// and requires the fingerprint value in the request body — this
// endpoint never reads a key off the wire itself. The expectation is
// an operator has confirmed the fingerprint out-of-band (console
// access, CMDB, or a supervised first connection reviewed by a human)
// before calling this. See postgres.HostKeyRegistry's doc comment for
// why this must never be automatic.
func (h *HostHandler) RegisterHostKey(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var req registerHostKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Fingerprint == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}

	if err := h.hostKeys.Register(r.Context(), id, req.Fingerprint, claims.UserID); err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// This action must be audited explicitly, per the doc comment on
	// HostKeyRegistry.Register: it changes what host identity this
	// application will trust.
	_ = h.audit.Write(r.Context(), &entity.AuditLog{
		Timestamp:     time.Now(),
		Username:      claims.Username,
		Action:        "host.register_key",
		HostID:        &id,
		Result:        "success",
		Detail:        "fingerprint=" + req.Fingerprint,
		CorrelationID: uuid.New().String(),
	})

	w.WriteHeader(http.StatusNoContent)
}
