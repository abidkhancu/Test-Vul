// Package ssh implements the SSH verification engine: connecting to
// managed RHEL hosts and running a fixed, read-only set of commands
// to check advisory/package/CVE remediation status.
//
// SAFETY INVARIANT (do not weaken without a full review): everything
// in this file is read-only. There is no function here, and there
// must never be one added, that can construct a package-modifying
// command (dnf update, dnf upgrade, yum update, bare rpm -i/-U, etc).
// Patch execution lives in a *separate* package (usecase/patch) whose
// only entry point requires an ApprovalToken that can only be minted
// by patch.Guard after checking a RemediationTask's approval state in
// the database. That separation is deliberate: a bug in the
// verification engine should never be able to escalate into running
// a patch, because the verification engine's package doesn't import
// anything capable of building a patch command at all.
package ssh

import (
	"fmt"
	"regexp"
)

// Strict validators for anything that gets interpolated into a shell
// command. Reject early and loudly rather than attempt to sanitize —
// an RHSA ID or package name that doesn't match these patterns is not
// a real RHSA ID or package name, and building a command from it is a
// bug or an injection attempt either way.
var (
	rhsaIDPattern      = regexp.MustCompile(`^RHSA-\d{4}:\d{3,6}$`)
	packageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	cvePattern         = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
)

func validateRHSAID(id string) error {
	if !rhsaIDPattern.MatchString(id) {
		return fmt.Errorf("invalid RHSA identifier %q: does not match RHSA-YYYY:NNNN", id)
	}
	return nil
}

func validatePackageName(name string) error {
	if !packageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package name %q: contains disallowed characters", name)
	}
	return nil
}

// ReadOnlyCommand is an opaque, already-validated command ready to
// send over an SSH session. It can only be constructed by the
// functions in this file. Verifier.run (in verifier.go) accepts only
// this type — never a raw string — so every code path that reaches
// an SSH session has necessarily gone through validation here.
type ReadOnlyCommand struct {
	label string // human-readable label for audit logs, e.g. "check_advisory"
	cmd   string
}

func (c ReadOnlyCommand) Label() string  { return c.label }
func (c ReadOnlyCommand) String() string { return c.cmd }

// CheckAdvisory: is this RHSA listed as a security advisory at all
// (installed or not) on this host's channel?
//
//	dnf updateinfo list security all | grep RHSA-XXXX
func CheckAdvisory(rhsaID string) (ReadOnlyCommand, error) {
	if err := validateRHSAID(rhsaID); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "check_advisory",
		cmd:   fmt.Sprintf("dnf updateinfo list security all 2>/dev/null | grep -F %q || true", rhsaID),
	}, nil
}

// ReviewAdvisory: full advisory detail (CVEs covered, packages,
// synopsis) for cross-referencing against what the correlation engine
// extracted from scanner text.
//
//	dnf updateinfo info RHSA-XXXX
func ReviewAdvisory(rhsaID string) (ReadOnlyCommand, error) {
	if err := validateRHSAID(rhsaID); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "review_advisory",
		cmd:   fmt.Sprintf("dnf updateinfo info %q 2>/dev/null", rhsaID),
	}, nil
}

// VerifyPackage: is the package installed, and at what version?
//
//	rpm -q package-name
func VerifyPackage(pkg string) (ReadOnlyCommand, error) {
	if err := validatePackageName(pkg); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "verify_package",
		cmd:   fmt.Sprintf("rpm -q %q 2>&1", pkg),
	}, nil
}

// VerifyChangelog: does the installed package's RPM changelog mention
// the CVE we're checking, confirming the fix landed in this build
// even if the version string alone is ambiguous?
//
//	rpm -q --changelog package-name | grep CVE
func VerifyChangelog(pkg string) (ReadOnlyCommand, error) {
	if err := validatePackageName(pkg); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "verify_changelog",
		cmd:   fmt.Sprintf("rpm -q --changelog %q 2>/dev/null | grep -F CVE || true", pkg),
	}, nil
}

// VerifyAdvisoryInstalled: has this specific RHSA already been
// applied on this host?
//
//	dnf updateinfo list installed | grep RHSA
func VerifyAdvisoryInstalled(rhsaID string) (ReadOnlyCommand, error) {
	if err := validateRHSAID(rhsaID); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "verify_advisory_installed",
		cmd:   fmt.Sprintf("dnf updateinfo list installed 2>/dev/null | grep -F %q || true", rhsaID),
	}, nil
}

// VerifyPendingUpdates: is this RHSA available but not yet applied?
//
//	dnf updateinfo list security available
func VerifyPendingUpdates(rhsaID string) (ReadOnlyCommand, error) {
	if err := validateRHSAID(rhsaID); err != nil {
		return ReadOnlyCommand{}, err
	}
	return ReadOnlyCommand{
		label: "verify_pending_updates",
		cmd:   fmt.Sprintf("dnf updateinfo list security available 2>/dev/null | grep -F %q || true", rhsaID),
	}, nil
}

// ValidCVE is exported only so callers (verifier.go) can validate a
// CVE string before logging/storing it; it never becomes part of a
// shell command in this package.
func ValidCVE(id string) bool {
	return cvePattern.MatchString(id)
}
