package entity

import "time"

// Severity is a normalized severity level across all scanner sources.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// NormalizeSeverity maps arbitrary scanner severity strings onto the
// platform's canonical Severity enum. Unrecognized values map to
// SeverityUnknown rather than failing the import.
func NormalizeSeverity(raw string) Severity {
	switch normalizeToken(raw) {
	case "critical", "crit", "4":
		return SeverityCritical
	case "high", "important", "3":
		return SeverityHigh
	case "medium", "moderate", "med", "2":
		return SeverityMedium
	case "low", "1":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// Package represents an RPM (or other) package name tracked for
// vulnerability correlation. Version is optional and only populated
// once verified against a live host.
type Package struct {
	ID               string `json:"id" db:"id"`
	Name             string `json:"name" db:"name"`
	InstalledVersion string `json:"installed_version,omitempty" db:"installed_version"`
	FixedVersion     string `json:"fixed_version,omitempty" db:"fixed_version"`
}

// CVE represents a single Common Vulnerabilities and Exposures record.
type CVE struct {
	ID          string    `json:"id" db:"id"` // e.g. CVE-2023-0286
	Description string    `json:"description,omitempty" db:"description"`
	Severity    Severity  `json:"severity" db:"severity"`
	CVSSScore   *float64  `json:"cvss_score,omitempty" db:"cvss_score"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// RHSAAdvisory represents a Red Hat Security Advisory, which may
// remediate multiple CVEs across multiple packages in a single patch.
type RHSAAdvisory struct {
	ID           string     `json:"id" db:"id"` // e.g. RHSA-2025:7937
	Synopsis     string     `json:"synopsis,omitempty" db:"synopsis"`
	Severity     Severity   `json:"severity" db:"severity"`
	IssuedAt     *time.Time `json:"issued_at,omitempty" db:"issued_at"`
	CVEIDs       []string   `json:"cve_ids,omitempty" db:"-"`       // populated via join table
	PackageNames []string   `json:"package_names,omitempty" db:"-"` // populated via join table
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

func normalizeToken(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}
		if r == ' ' || r == '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
