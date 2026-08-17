package importer

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"

	"github.com/rs/zerolog"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/extraction"
)

// flushEvery controls how many parsed findings accumulate before a
// BulkInsert call, keeping memory bounded for very large CSV files
// (100k+ rows) while still batching writes for throughput.
const flushEvery = 1000

type CSVImporter struct {
	findings     repository.FindingRepository
	imports      repository.ImportRepository
	extractor    *extraction.Extractor
	hostResolver *HostResolver
	log          zerolog.Logger
}

func NewCSVImporter(findings repository.FindingRepository, imports repository.ImportRepository, extractor *extraction.Extractor, hostResolver *HostResolver, log zerolog.Logger) *CSVImporter {
	return &CSVImporter{findings: findings, imports: imports, extractor: extractor, hostResolver: hostResolver, log: log.With().Str("component", "csv_importer").Logger()}
}

// Import streams a CSV file, normalizes each row, runs extraction,
// and bulk-inserts findings. It updates the ImportBatch's row
// counters as it goes so progress is visible to the UI for
// large/async imports.
func (imp *CSVImporter) Import(ctx context.Context, batch *entity.ImportBatch, r io.Reader) error {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // tolerate ragged rows rather than failing the whole file
	reader.LazyQuotes = true

	headerRow, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read header row: %w", err)
	}
	hm := BuildHeaderMap(headerRow)

	var pending []*entity.ScannerFinding
	rowNum := 1 // header was row 0

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := imp.findings.BulkInsert(ctx, pending); err != nil {
			return fmt.Errorf("bulk insert at row %d: %w", rowNum, err)
		}
		batch.ProcessedRows += len(pending)
		pending = pending[:0]
		return imp.imports.UpdateBatch(ctx, batch)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A single malformed row shouldn't abort a 100k-row
			// import; count it and move on.
			batch.FailedRows++
			imp.log.Warn().Err(err).Int("row", rowNum).Msg("skipping malformed CSV row")
			rowNum++
			continue
		}
		rowNum++

		finding := RowToFinding(hm, row, batch.ID)
		result := imp.extractor.Extract(finding)
		finding.ExtractedCVEs = result.CVEs
		finding.ExtractedRHSAs = result.RHSAs
		finding.ExtractedPackages = result.Packages

		hostID, err := imp.hostResolver.Resolve(ctx, finding.HostRaw)
		if err != nil {
			// Host resolution failing shouldn't sink the whole
			// import — this finding just won't be host_id-set and
			// therefore won't be picked up by correlation until it's
			// manually triaged; log and continue rather than abort.
			imp.log.Warn().Err(err).Str("host_raw", finding.HostRaw).Int("row", rowNum).Msg("failed to resolve host for finding")
		} else {
			finding.HostID = hostID
		}

		pending = append(pending, finding)
		if len(pending) >= flushEvery {
			if err := flush(); err != nil {
				return err
			}
		}
	}

	if err := flush(); err != nil {
		return err
	}

	batch.TotalRows = batch.ProcessedRows + batch.FailedRows
	if batch.FailedRows > 0 {
		batch.Status = entity.ImportStatusPartial
	} else {
		batch.Status = entity.ImportStatusCompleted
	}
	return imp.imports.UpdateBatch(ctx, batch)
}
