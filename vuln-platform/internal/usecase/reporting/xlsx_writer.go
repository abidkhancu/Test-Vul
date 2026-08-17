package reporting

import (
	"bytes"
	"fmt"

	"github.com/xuri/excelize/v2"
)

// WriteXLSX renders a Table to a single-sheet XLSX workbook with a
// bold header row and auto-sized-ish column widths (excelize doesn't
// auto-fit, so a simple heuristic based on header length is used
// rather than leaving every column at default width).
func WriteXLSX(t Table) ([]byte, error) {
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	sheet := "Report"
	f.SetSheetName(f.GetSheetName(0), sheet)

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"1F2937"}, Pattern: 1},
	})
	if err != nil {
		return nil, fmt.Errorf("create header style: %w", err)
	}

	for col, header := range t.Headers {
		cell, err := excelize.CoordinatesToCellName(col+1, 1)
		if err != nil {
			return nil, err
		}
		if err := f.SetCellValue(sheet, cell, header); err != nil {
			return nil, err
		}
		colLetter, _ := excelize.ColumnNumberToName(col + 1)
		width := float64(len(header)) + 4
		if width < 12 {
			width = 12
		}
		if width > 40 {
			width = 40
		}
		if err := f.SetColWidth(sheet, colLetter, colLetter, width); err != nil {
			return nil, err
		}
	}
	if len(t.Headers) > 0 {
		endCell, _ := excelize.CoordinatesToCellName(len(t.Headers), 1)
		if err := f.SetCellStyle(sheet, "A1", endCell, headerStyle); err != nil {
			return nil, err
		}
	}

	for rowIdx, row := range t.Rows {
		for colIdx, value := range row {
			cell, err := excelize.CoordinatesToCellName(colIdx+1, rowIdx+2)
			if err != nil {
				return nil, err
			}
			if err := f.SetCellValue(sheet, cell, value); err != nil {
				return nil, err
			}
		}
	}

	if err := f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	}); err != nil {
		return nil, fmt.Errorf("freeze header row: %w", err)
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("write xlsx: %w", err)
	}
	return buf.Bytes(), nil
}
