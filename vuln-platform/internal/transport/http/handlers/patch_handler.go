package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/repository"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
	"github.com/ubank/vuln-platform/internal/usecase/patch"
)

type PatchHandler struct {
	executor  *patch.Executor
	patchJobs repository.PatchJobRepository
}

func NewPatchHandler(executor *patch.Executor, patchJobs repository.PatchJobRepository) *PatchHandler {
	return &PatchHandler{executor: executor, patchJobs: patchJobs}
}

type executePatchRequest struct {
	RemediationTaskID string `json:"remediation_task_id"`
}

// POST /api/v1/patches/execute
//
// Mounted behind middleware.RequirePatchApprover — but note that RBAC
// here only confirms the caller may *initiate* a patch execution
// request. The actual authorization to run a mutating command is a
// separate, stricter check: patch.Executor.Run calls patch.Guard.Authorize
// internally, which re-reads the RemediationTask's approval state from
// the database. A user with the right role hitting this endpoint for
// a task that isn't in the 'approved' state gets a 409, not a patch.
func (h *PatchHandler) Execute(w http.ResponseWriter, r *http.Request) {
	var req executePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RemediationTaskID == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "remediation_task_id is required")
		return
	}

	job, err := h.executor.Run(r.Context(), req.RemediationTaskID)
	if err != nil {
		vhttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	vhttp.WriteJSON(w, http.StatusAccepted, job)
}

// GET /api/v1/patches/by-task/{taskID}
func (h *PatchHandler) ListByTask(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")
	jobs, err := h.patchJobs.ListByTask(r.Context(), taskID)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list patch jobs")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, jobs)
}

// GET /api/v1/patches/{id}
func (h *PatchHandler) Get(w http.ResponseWriter, r *http.Request) {
	job, err := h.patchJobs.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "patch job not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, job)
}
