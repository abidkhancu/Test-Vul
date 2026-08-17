// Package importer implements the CSV/XLSX vulnerability report
// import pipeline: column-flexible parsing, normalization, and
// handoff to the extraction engine. Unknown columns are ignored;
// missing expected columns degrade gracefully rather than failing
// the whole import, per spec.
package importer

import (
	"strconv"
	"strings"
	"time"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

// expectedColumns lists every column the spec calls out. Header
// matching is case-insensitive and tolerant of extra whitespace /
// underscores vs spaces, since real-world exports from Qualys,
// Nessus, Tenable, etc. all format headers slightly differently.
var columnAliases = map[string][]string{
	"source":               {"source", "scanner", "scanner_name"},
	"id":                   {"id", "source_id", "finding_id", "vuln_id"},
	"name":                 {"name", "title", "vulnerability", "vulnerability_name"},
	"description":          {"description", "desc"},
	"severity":             {"severity", "risk", "risk_level"},
	"status":               {"status", "state"},
	"reported_on":          {"reported_on", "reported_date", "date_reported", "first_detected"},
	"closure_date":         {"closure_date", "date_closed", "resolved_date"},
	"impact":               {"impact"},
	"solution":             {"solution", "remediation", "fix"},
	"assessment_type":      {"assessment_type", "scan_type", "assessment"},
	"age":                  {"age", "age_days", "age_in_days"},
	"days_for_closure":     {"days_for_closure", "days_to_close"},
	"closure_by_exception": {"closure_by_exception", "exception", "risk_accepted"},
	"comments":             {"comments", "notes", "comment"},
	"host":                 {"host/application", "host", "application", "hostname", "asset"},
}

// dateLayouts are attempted in order when parsing date columns.
// Real-world exports vary widely; we try the common ones and fall
// back to leaving the field nil rather than failing the row.
var dateLayouts = []string{
	"2006-01-02",
	"01/02/2006",
	"02-01-2006",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"Jan 2, 2006",
	"02 Jan 2006",
}

// HeaderMap resolves a raw header row into a canonical-name -> column-index
// map, so both the CSV and XLSX importers can share one row-parsing
// function regardless of column order or exact header text.
type HeaderMap map[string]int

func BuildHeaderMap(headers []string) HeaderMap {
	hm := make(HeaderMap)
	for idx, raw := range headers {
		norm := normalizeHeader(raw)
		for canonical, aliases := range columnAliases {
			for _, a := range aliases {
				if norm == a {
					hm[canonical] = idx
				}
			}
		}
	}
	return hm
}

func normalizeHeader(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.ReplaceAll(h, " ", "_")
	h = strings.ReplaceAll(h, "-", "_")
	return h
}

// get safely reads a column by canonical name from a row, returning
// "" if that column wasn't present in this file at all — this is how
// "missing columns should not cause failures" is satisfied.
func (hm HeaderMap) get(row []string, canonical string) string {
	idx, ok := hm[canonical]
	if !ok || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

// RowToFinding converts one raw row into a normalized ScannerFinding.
// It never returns an error for missing/malformed optional fields;
// it only fails for conditions that make the row unusable entirely
// (currently: none — even a mostly-empty row is imported as-is and
// left for manual triage, since silently dropping scanner data is
// worse than importing a sparse record).
func RowToFinding(hm HeaderMap, row []string, importID string) *entity.ScannerFinding {
	f := &entity.ScannerFinding{
		ImportID:           importID,
		Source:             hm.get(row, "source"),
		SourceID:           hm.get(row, "id"),
		Name:               hm.get(row, "name"),
		Description:        hm.get(row, "description"),
		Impact:             hm.get(row, "impact"),
		Solution:           hm.get(row, "solution"),
		AssessmentType:     hm.get(row, "assessment_type"),
		Comments:           hm.get(row, "comments"),
		HostRaw:            hm.get(row, "host"),
		Severity:           entity.NormalizeSeverity(hm.get(row, "severity")),
		Status:             normalizeStatus(hm.get(row, "status")),
		ClosureByException: parseBool(hm.get(row, "closure_by_exception")),
	}

	if t, ok := parseDate(hm.get(row, "reported_on")); ok {
		f.ReportedOn = &t
	}
	if t, ok := parseDate(hm.get(row, "closure_date")); ok {
		f.ClosureDate = &t
	}
	if n, ok := parseInt(hm.get(row, "age")); ok {
		f.AgeDays = &n
	}
	if n, ok := parseInt(hm.get(row, "days_for_closure")); ok {
		f.DaysForClosure = &n
	}

	return f
}

func normalizeStatus(raw string) entity.FindingStatus {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "closed", "resolved", "fixed":
		return entity.FindingStatusClosed
	case "false positive", "false_positive", "falsepositive":
		return entity.FindingStatusFalsePositive
	default:
		return entity.FindingStatusOpen
	}
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "y", "1":
		return true
	default:
		return false
	}
}

func parseInt(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseDate(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
