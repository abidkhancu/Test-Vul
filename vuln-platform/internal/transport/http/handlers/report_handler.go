package handlers

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	"github.com/ubank/vuln-platform/internal/usecase/reporting"

	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

type ReportHandler struct {
	generator *reporting.Generator
	reports   repository.ReportRepository
}

func NewReportHandler(generator *reporting.Generator, reports repository.ReportRepository) *ReportHandler {
	return &ReportHandler{generator: generator, reports: reports}
}

var validReportTypes = map[entity.ReportType]struct{}{
	entity.ReportExecutiveSummary: {}, entity.ReportTechnical: {}, entity.ReportHost: {},
	entity.ReportPackage: {}, entity.ReportRHSA: {}, entity.ReportCVE: {},
	entity.ReportVerification: {}, entity.ReportPatch: {}, entity.ReportAudit: {},
}

var validReportFormats = map[entity.ReportFormat]string{
	entity.ReportFormatPDF:  "application/pdf",
	entity.ReportFormatCSV:  "text/csv",
	entity.ReportFormatXLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

// POST /api/v1/reports?type=executive_summary&format=pdf
//
// Generates synchronously and streams the result back directly (in
// addition to persisting it — see reporting.Generator.Generate) since
// even the largest report here is bounded by maxRows and renders in
// well under a request timeout. Move to the async worker pool pattern
// (like imports) if report generation grows to need a background job.
func (h *ReportHandler) Generate(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())

	reportType := entity.ReportType(r.URL.Query().Get("type"))
	format := entity.ReportFormat(r.URL.Query().Get("format"))

	if _, ok := validReportTypes[reportType]; !ok {
		vhttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid report type %q", reportType))
		return
	}
	contentType, ok := validReportFormats[format]
	if !ok {
		vhttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid report format %q", format))
		return
	}

	report, data, err := h.generator.Generate(r.Context(), reportType, format, claims.UserID)
	if err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("%s.%s", reportType, format)))
	w.Header().Set("X-Report-ID", report.ID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// GET /api/v1/reports?type=
func (h *ReportHandler) List(w http.ResponseWriter, r *http.Request) {
	reportType := entity.ReportType(r.URL.Query().Get("type"))
	reports, err := h.reports.List(r.Context(), reportType, 50)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list reports")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, reports)
}

// GET /api/v1/reports/{id}/download
func (h *ReportHandler) Download(w http.ResponseWriter, r *http.Request) {
	report, err := h.reports.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "report not found")
		return
	}

	data, err := os.ReadFile(report.StoragePath)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "report file is no longer available on disk")
		return
	}

	contentType := validReportFormats[report.Format]
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("%s.%s", report.ReportType, report.Format)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
