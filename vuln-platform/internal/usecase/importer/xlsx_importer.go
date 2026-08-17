package importer

import (
	"context"
	"fmt"
	"io"

	"github.com/rs/zerolog"
	"github.com/xuri/excelize/v2"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/extraction"
)

type XLSXImporter struct {
	findings     repository.FindingRepository
	imports      repository.ImportRepository
	extractor    *extraction.Extractor
	hostResolver *HostResolver
	log          zerolog.Logger
}

func NewXLSXImporter(findings repository.FindingRepository, imports repository.ImportRepository, extractor *extraction.Extractor, hostResolver *HostResolver, log zerolog.Logger) *XLSXImporter {
	return &XLSXImporter{findings: findings, imports: imports, extractor: extractor, hostResolver: hostResolver, log: log.With().Str("component", "xlsx_importer").Logger()}
}

// Import uses excelize's streaming row reader so large XLSX files
// don't get fully materialized in memory. It reads the first sheet
// by default; pass a specific SheetName via ImportOptions if a
// report uses multiple tabs.
func (imp *XLSXImporter) Import(ctx context.Context, batch *entity.ImportBatch, r io.Reader, sheetName string) error {
	f, err := excelize.OpenReader(r)
	if err != nil {
		return fmt.Errorf("open xlsx: %w", err)
	}
	defer func() { _ = f.Close() }()

	if sheetName == "" {
		sheetName = f.GetSheetName(0)
	}

	rows, err := f.Rows(sheetName)
	if err != nil {
		return fmt.Errorf("open sheet %q: %w", sheetName, err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		return fmt.Errorf("sheet %q is empty", sheetName)
	}
	headerRow, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("read header row: %w", err)
	}
	hm := BuildHeaderMap(headerRow)

	var pending []*entity.ScannerFinding
	rowNum := 1

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

	for rows.Next() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		row, err := rows.Columns()
		rowNum++
		if err != nil {
			batch.FailedRows++
			imp.log.Warn().Err(err).Int("row", rowNum).Msg("skipping unreadable XLSX row")
			continue
		}

		finding := RowToFinding(hm, row, batch.ID)
		result := imp.extractor.Extract(finding)
		finding.ExtractedCVEs = result.CVEs
		finding.ExtractedRHSAs = result.RHSAs
		finding.ExtractedPackages = result.Packages

		hostID, err := imp.hostResolver.Resolve(ctx, finding.HostRaw)
		if err != nil {
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
