package handlers

import (
	"net/http"

	"github.com/ubank/vuln-platform/internal/domain/repository"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

type AuditHandler struct {
	audit repository.AuditRepository
}

func NewAuditHandler(audit repository.AuditRepository) *AuditHandler {
	return &AuditHandler{audit: audit}
}

// GET /api/v1/audit?username=&action=&host_id=&page=&page_size=
//
// Administrator-only (enforced by the router) — the audit trail
// itself is sensitive: it reveals every command run against every
// host, by whom, and when.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	f := repository.AuditFilter{
		Username: r.URL.Query().Get("username"),
		Action:   r.URL.Query().Get("action"),
		HostID:   r.URL.Query().Get("host_id"),
		Page:     page,
		PageSize: pageSize,
	}
	logs, total, err := h.audit.Query(r.Context(), f)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]interface{}{"entries": logs, "total": total})
}
