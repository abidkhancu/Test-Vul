package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
	"github.com/ubank/vuln-platform/internal/usecase/ssh"
)

type RemediationHandler struct {
	remediation repository.RemediationRepository
	verifier    *ssh.Verifier
}

func NewRemediationHandler(remediation repository.RemediationRepository, verifier *ssh.Verifier) *RemediationHandler {
	return &RemediationHandler{remediation: remediation, verifier: verifier}
}

// GET /api/v1/remediation?status=&severity=&host_id=&page=&page_size=
func (h *RemediationHandler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	f := repository.RemediationFilter{
		Status:   entity.RemediationStatus(r.URL.Query().Get("status")),
		Severity: entity.Severity(r.URL.Query().Get("severity")),
		HostID:   r.URL.Query().Get("host_id"),
		Page:     page,
		PageSize: pageSize,
	}
	tasks, total, err := h.remediation.List(r.Context(), f)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list remediation tasks")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]interface{}{"tasks": tasks, "total": total})
}

// GET /api/v1/remediation/{id}
func (h *RemediationHandler) Get(w http.ResponseWriter, r *http.Request) {
	task, err := h.remediation.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "remediation task not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, task)
}

// POST /api/v1/remediation/{id}/verify
//
// Triggers a read-only SSH verification pass for this task on demand
// (in addition to whatever the periodic scheduler does). Any
// authenticated user whose role permits verification (operator,
// security_analyst, administrator) may call this — it never touches
// package state, so it doesn't need patch-approver-level permission.
func (h *RemediationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !claims.Role.CanRunVerification() {
		vhttp.WriteError(w, http.StatusForbidden, "your role cannot trigger verification")
		return
	}

	task, err := h.remediation.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "remediation task not found")
		return
	}

	result, err := h.verifier.Verify(r.Context(), task)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "verification failed to run: "+err.Error())
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, result)
}

type approveRequest struct {
	Comment string `json:"comment,omitempty"`
}

// POST /api/v1/remediation/{id}/approve
//
// Mounted behind middleware.RequirePatchApprover in the router — by
// the time this handler runs, RBAC has already confirmed the caller
// holds patch_approver or administrator. This handler still passes
// claims.UserID explicitly to Approve() rather than trusting any
// client-supplied field, so the audit trail records who actually
// approved it based on their authenticated identity.
func (h *RemediationHandler) Approve(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.remediation.Approve(r.Context(), id, claims.UserID); err != nil {
		vhttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type rejectRequest struct {
	Reason string `json:"reason"`
}

// POST /api/v1/remediation/{id}/reject
func (h *RemediationHandler) Reject(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var req rejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reason == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "a reason is required to reject a remediation task")
		return
	}

	if err := h.remediation.Reject(r.Context(), id, claims.UserID, req.Reason); err != nil {
		vhttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
