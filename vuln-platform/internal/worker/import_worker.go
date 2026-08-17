// Package worker implements the background worker pool that processes
// import jobs and correlation passes off the request path, so a
// 100k-row XLSX upload returns immediately with an ImportBatch ID
// while processing continues asynchronously.
package worker

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/correlation"
	"github.com/ubank/vuln-platform/internal/usecase/importer"
)

// ImportJob is enqueued by the HTTP upload handler once a file has
// been written to temporary storage. The worker owns opening/closing
// the file so the HTTP handler doesn't hold it open across the async
// boundary.
type ImportJob struct {
	BatchID   string
	FilePath  string
	FileType  string // "csv" | "xlsx"
	SheetName string // optional, xlsx only
}

type Pool struct {
	jobs         chan ImportJob
	imports      repository.ImportRepository
	csvImporter  *importer.CSVImporter
	xlsxImporter *importer.XLSXImporter
	correlator   *correlation.Correlator
	log          zerolog.Logger
}

// NewPool wires a bounded worker pool. concurrency should be tuned to
// available DB connection headroom — each worker holds a DB
// connection for the duration of its BulkInsert calls — not to CPU
// count, since the work here is I/O bound (parsing + DB writes).
func NewPool(
	concurrency int,
	queueDepth int,
	imports repository.ImportRepository,
	csvImporter *importer.CSVImporter,
	xlsxImporter *importer.XLSXImporter,
	correlator *correlation.Correlator,
	log zerolog.Logger,
) *Pool {
	p := &Pool{
		jobs:         make(chan ImportJob, queueDepth),
		imports:      imports,
		csvImporter:  csvImporter,
		xlsxImporter: xlsxImporter,
		correlator:   correlator,
		log:          log.With().Str("component", "import_worker_pool").Logger(),
	}
	for i := 0; i < concurrency; i++ {
		go p.runWorker(i)
	}
	return p
}

// Enqueue submits a job without blocking the caller indefinitely; if
// the queue is full it returns an error so the HTTP layer can respond
// with 503/backpressure rather than hanging the request.
func (p *Pool) Enqueue(job ImportJob) error {
	select {
	case p.jobs <- job:
		return nil
	default:
		return fmt.Errorf("import queue full (depth=%d): try again shortly", cap(p.jobs))
	}
}

func (p *Pool) runWorker(id int) {
	log := p.log.With().Int("worker_id", id).Logger()
	for job := range p.jobs {
		p.process(log, job)
	}
}

func (p *Pool) process(log zerolog.Logger, job ImportJob) {
	// Each job gets its own timeout-bounded context so a stuck parse
	// on one bad file can't wedge a worker goroutine forever.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	log = log.With().Str("batch_id", job.BatchID).Str("file", job.FilePath).Logger()
	log.Info().Msg("starting import job")

	batch, err := p.imports.GetBatch(ctx, job.BatchID)
	if err != nil {
		log.Error().Err(err).Msg("failed to load import batch")
		return
	}
	now := time.Now()
	batch.Status = entity.ImportStatusProcessing
	batch.StartedAt = &now
	if err := p.imports.UpdateBatch(ctx, batch); err != nil {
		log.Error().Err(err).Msg("failed to mark batch processing")
		return
	}

	file, err := os.Open(job.FilePath)
	if err != nil {
		p.failBatch(ctx, log, batch, fmt.Errorf("open file: %w", err))
		return
	}
	defer func() { _ = file.Close() }()

	switch job.FileType {
	case "csv":
		err = p.csvImporter.Import(ctx, batch, file)
	case "xlsx":
		err = p.xlsxImporter.Import(ctx, batch, file, job.SheetName)
	default:
		err = fmt.Errorf("unsupported file type %q", job.FileType)
	}
	if err != nil {
		p.failBatch(ctx, log, batch, err)
		return
	}

	completed := time.Now()
	batch.CompletedAt = &completed
	if err := p.imports.UpdateBatch(ctx, batch); err != nil {
		log.Error().Err(err).Msg("failed to finalize batch status")
	}
	log.Info().Int("processed", batch.ProcessedRows).Int("failed", batch.FailedRows).Msg("import complete, starting correlation pass")

	if _, err := p.correlator.Run(ctx); err != nil {
		log.Error().Err(err).Msg("post-import correlation pass failed")
	}
}

func (p *Pool) failBatch(ctx context.Context, log zerolog.Logger, batch *entity.ImportBatch, cause error) {
	log.Error().Err(cause).Msg("import job failed")
	batch.Status = entity.ImportStatusFailed
	batch.ErrorSummary = cause.Error()
	now := time.Now()
	batch.CompletedAt = &now
	if err := p.imports.UpdateBatch(ctx, batch); err != nil {
		log.Error().Err(err).Msg("failed to record batch failure")
	}
}
