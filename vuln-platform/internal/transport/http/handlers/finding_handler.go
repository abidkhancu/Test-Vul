package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

type FindingHandler struct {
	findings repository.FindingRepository
}

func NewFindingHandler(findings repository.FindingRepository) *FindingHandler {
	return &FindingHandler{findings: findings}
}

// GET /api/v1/findings?severity=&status=&host_id=&search=
func (h *FindingHandler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	f := repository.FindingFilter{
		Severity: entity.Severity(r.URL.Query().Get("severity")),
		Status:   entity.FindingStatus(r.URL.Query().Get("status")),
		HostID:   r.URL.Query().Get("host_id"),
		Search:   r.URL.Query().Get("search"),
		Page:     page,
		PageSize: pageSize,
	}
	findings, total, err := h.findings.List(r.Context(), f)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list findings (note: pagination not yet implemented — see repository TODO)")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]interface{}{"findings": findings, "total": total})
}

// GET /api/v1/findings/{id}
func (h *FindingHandler) Get(w http.ResponseWriter, r *http.Request) {
	finding, err := h.findings.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "finding not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, finding)
}
