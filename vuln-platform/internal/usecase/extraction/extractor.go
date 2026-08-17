// Package extraction implements the CVE / RHSA / package-name
// extraction engine described in the platform spec. It scans the
// free-text fields of a scanner finding (Name, Description, Impact,
// Solution) and pulls out normalized identifiers for downstream
// correlation.
//
// The engine is intentionally regex-first: CVE and RHSA identifiers
// follow strict, stable formats (CVE-YYYY-NNNN..., RHSA-YYYY:NNNN),
// so regex gives precise, auditable extraction. Package-name
// recognition is heuristic (known package list + common naming
// patterns) since free text doesn't delimit package names reliably;
// treat those hits as suggestions to confirm during SSH verification,
// not ground truth.
package extraction

import (
	"regexp"
	"sort"
	"strings"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

var (
	// CVE-YYYY-NNNN (4 to 7 digit sequence number per the CVE spec).
	cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

	// RHSA-YYYY:NNNN
	rhsaRegex = regexp.MustCompile(`RHSA-\d{4}:\d{3,6}`)

	// RHBA (bug advisory) and RHEA (enhancement advisory) sometimes
	// appear alongside RHSA in scanner text; capture them separately
	// so they don't get miscounted as security advisories.
	rhbaRegex = regexp.MustCompile(`RHBA-\d{4}:\d{3,6}`)
	rheaRegex = regexp.MustCompile(`RHEA-\d{4}:\d{3,6}`)
)

// knownPackagePatterns is a curated, extensible set of package-name
// matchers for packages commonly seen in RHEL security advisories.
// This is not exhaustive; it's a starting point that should be
// extended from your own advisory corpus (e.g. by mining historical
// RHSA package lists) and can be augmented at runtime via
// Extractor.AddKnownPackages.
var defaultKnownPackages = []string{
	"kernel", "kernel-core", "kernel-modules", "kernel-headers", "kernel-tools",
	"openssl", "openssl-libs", "compat-openssl11", "compat-openssl10",
	"podman", "buildah", "skopeo", "runc", "crun", "containernetworking-plugins",
	"cri-o", "cri-tools",
	"glibc", "glibc-common", "glib2",
	"systemd", "systemd-libs", "systemd-udev",
	"curl", "libcurl", "nghttp2",
	"python3", "python3-libs", "python3-pip", "python39", "python311", "python312",
	"nodejs", "npm",
	"sudo", "polkit", "dbus", "dbus-daemon",
	"sqlite", "sqlite-libs",
	"krb5-libs", "cyrus-sasl-lib",
	"nss", "nss-util", "nss-softokn",
	"bind", "bind-utils", "bind-libs",
	"httpd", "httpd-tools", "mod_ssl", "nginx",
	"java-1.8.0-openjdk", "java-11-openjdk", "java-17-openjdk", "java-21-openjdk",
	"postgresql", "postgresql-server", "mariadb", "mariadb-server",
	"vim-minimal", "vim-common", "vim-enhanced",
	"gzip", "tar", "zlib", "xz", "xz-libs",
	"expat", "libxml2", "libxslt",
	"grub2", "grub2-common", "shim", "shim-x64",
	"NetworkManager", "iptables", "nftables", "firewalld",
	"selinux-policy", "selinux-policy-targeted",
}

type Extractor struct {
	knownPackages map[string]struct{}
}

func New() *Extractor {
	e := &Extractor{knownPackages: make(map[string]struct{}, len(defaultKnownPackages))}
	for _, p := range defaultKnownPackages {
		e.knownPackages[strings.ToLower(p)] = struct{}{}
	}
	return e
}

// AddKnownPackages extends the recognized package vocabulary at
// runtime, e.g. loaded from a DB table populated by ingesting your
// Satellite/Insights package catalog.
func (e *Extractor) AddKnownPackages(names ...string) {
	for _, n := range names {
		e.knownPackages[strings.ToLower(n)] = struct{}{}
	}
}

// Result holds everything extracted from a single finding's text
// fields, deduplicated and sorted for deterministic output.
type Result struct {
	CVEs     []string
	RHSAs    []string
	RHBAs    []string
	RHEAs    []string
	Packages []string
}

// Extract scans the given finding's free-text fields and returns
// normalized, deduplicated identifiers. It mutates nothing on the
// finding; callers should assign the result fields onto
// finding.ExtractedCVEs / ExtractedRHSAs / ExtractedPackages
// themselves so the extraction step stays a pure function.
func (e *Extractor) Extract(f *entity.ScannerFinding) Result {
	text := strings.Join([]string{f.Name, f.Description, f.Impact, f.Solution}, "\n")

	res := Result{
		CVEs:     dedupUpper(cveRegex.FindAllString(text, -1)),
		RHSAs:    dedupUpper(rhsaRegex.FindAllString(text, -1)),
		RHBAs:    dedupUpper(rhbaRegex.FindAllString(text, -1)),
		RHEAs:    dedupUpper(rheaRegex.FindAllString(text, -1)),
		Packages: e.extractPackages(text),
	}
	return res
}

// extractPackages tokenizes the text and checks tokens (and
// hyphen-joined bigrams/trigrams, since package names like
// "compat-openssl11" or "java-17-openjdk" contain hyphens) against
// the known-package vocabulary. This deliberately favors precision
// over recall: a false negative just means the package needs to be
// confirmed during SSH verification anyway; a false positive would
// pollute the correlation graph.
func (e *Extractor) extractPackages(text string) []string {
	// Split on whitespace and common punctuation, but keep hyphens
	// and dots since they're part of package/version syntax.
	fields := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', ',', ';', ':', '(', ')', '[', ']', '"', '\'':
			return true
		default:
			return false
		}
	})

	found := make(map[string]struct{})
	for _, tok := range fields {
		tok = strings.Trim(tok, ".")
		lower := strings.ToLower(tok)

		// Store the canonical lowercase form, not the original-case
		// token. Real RPM package names are conventionally all
		// lowercase; storing whatever case the scanner text happened
		// to use (e.g. "OpenSSL" in a vulnerability title vs.
		// "compat-openssl11" in the description) produces duplicate,
		// non-canonical entries that pollute the correlation engine's
		// package list and would waste an `rpm -q OpenSSL` SSH
		// verification command that can never match a real package.
		if _, ok := e.knownPackages[lower]; ok {
			found[lower] = struct{}{}
			continue
		}

		// Strip a trailing version/arch suffix like
		// "-1.2.3-4.el9.x86_64" and retry, since scanner text often
		// includes full NEVRA strings rather than bare package names.
		if base, ok := stripNEVRA(lower); ok {
			if _, ok := e.knownPackages[base]; ok {
				found[base] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stripNEVRA attempts to strip a trailing "-<version>-<release>.<dist>.<arch>"
// suffix from a package token, returning the bare package name.
// Example: "compat-openssl11-1.1.1k-11.el9.x86_64" -> "compat-openssl11".
func stripNEVRA(tok string) (string, bool) {
	parts := strings.Split(tok, "-")
	if len(parts) < 3 {
		return "", false
	}
	// Heuristic: walk from the end, drop segments that look like a
	// version (start with a digit) or contain ".el" / arch markers.
	end := len(parts)
	for end > 1 {
		seg := parts[end-1]
		if len(seg) == 0 {
			end--
			continue
		}
		if seg[0] >= '0' && seg[0] <= '9' {
			end--
			continue
		}
		if strings.Contains(seg, ".el") || seg == "x86_64" || seg == "aarch64" || seg == "noarch" || seg == "i686" {
			end--
			continue
		}
		break
	}
	if end == len(parts) || end == 0 {
		return "", false
	}
	return strings.Join(parts[:end], "-"), true
}

func dedupUpper(matches []string) []string {
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		u := strings.ToUpper(m)
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}
