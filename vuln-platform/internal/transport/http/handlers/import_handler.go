package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
	"github.com/ubank/vuln-platform/internal/worker"
)

type ImportHandler struct {
	imports     repository.ImportRepository
	importPool  *worker.Pool
	uploadDir   string
	maxFileSize int64 // bytes
}

func NewImportHandler(imports repository.ImportRepository, importPool *worker.Pool, uploadDir string, maxFileSizeMB int) *ImportHandler {
	return &ImportHandler{
		imports:     imports,
		importPool:  importPool,
		uploadDir:   uploadDir,
		maxFileSize: int64(maxFileSizeMB) * 1024 * 1024,
	}
}

// POST /api/v1/imports (multipart/form-data, field "file")
//
// Writes the upload to disk, creates an ImportBatch row immediately
// (so the client gets an ID to poll), and enqueues background
// processing — the request returns as soon as the file is safely on
// disk, not after the (potentially 100k-row) file finishes importing.
func (h *ImportHandler) Upload(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse upload (max size %dMB): %v", h.maxFileSize/(1024*1024), err))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, "missing 'file' field in multipart form")
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	fileType := ""
	switch ext {
	case ".csv":
		fileType = "csv"
	case ".xlsx":
		fileType = "xlsx"
	default:
		vhttp.WriteError(w, http.StatusBadRequest, "only .csv and .xlsx files are supported")
		return
	}

	batch := &entity.ImportBatch{
		Filename:   header.Filename,
		FileType:   fileType,
		Status:     entity.ImportStatusPending,
		UploadedBy: claims.UserID,
	}
	if err := h.imports.CreateBatch(r.Context(), batch); err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to create import batch record")
		return
	}

	if err := os.MkdirAll(h.uploadDir, 0o750); err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to prepare upload directory")
		return
	}
	destPath := filepath.Join(h.uploadDir, batch.ID+ext)
	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to save uploaded file")
		return
	}
	if _, err := io.Copy(dest, file); err != nil {
		dest.Close()
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to save uploaded file")
		return
	}
	dest.Close()

	if err := h.importPool.Enqueue(worker.ImportJob{BatchID: batch.ID, FilePath: destPath, FileType: fileType}); err != nil {
		vhttp.WriteError(w, http.StatusServiceUnavailable, "import queue is full; try again shortly")
		return
	}

	vhttp.WriteJSON(w, http.StatusAccepted, batch)
}

// GET /api/v1/imports/{id}
func (h *ImportHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	batch, err := h.imports.GetBatch(r.Context(), id)
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "import batch not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, batch)
}

// GET /api/v1/imports?limit=20
func (h *ImportHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	batches, err := h.imports.ListRecent(r.Context(), limit)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list imports")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, batches)
}
