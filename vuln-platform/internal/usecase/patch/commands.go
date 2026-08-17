package patch

import "fmt"

// PatchCommand is an opaque, pre-validated command string. Like
// ssh.ReadOnlyCommand, it can only be constructed by functions in
// this file, and those functions require an ApprovalToken — there is
// no path to a PatchCommand that skips Guard.Authorize.
type PatchCommand struct {
	cmd              string
	fullSystemUpdate bool
}

func (c PatchCommand) String() string           { return c.cmd }
func (c PatchCommand) IsFullSystemUpdate() bool { return c.fullSystemUpdate }

// BuildAdvisoryPatch constructs the single-advisory patch command:
//
//	dnf update --advisory=RHSA-YYYY:NNNN
//
// This targets exactly the approved advisory and nothing else — it
// will not pull in unrelated package updates the way a bare
// `dnf update` would.
func BuildAdvisoryPatch(token ApprovalToken) (PatchCommand, error) {
	if token.rhsaID == "" {
		return PatchCommand{}, fmt.Errorf("approval token has no RHSA id; this should be unreachable — Guard.Authorize validates this")
	}
	if token.fullSystemUpdate {
		return PatchCommand{}, fmt.Errorf("token was authorized for full system update; use BuildFullSystemUpdate instead")
	}
	return PatchCommand{
		cmd: fmt.Sprintf("sudo dnf update --advisory=%s -y", token.rhsaID),
	}, nil
}

// BuildFullSystemUpdate constructs the spec's one explicitly-allowed
// exception to "never dnf update -y": a full system update, and only
// when the token was minted via Guard.AuthorizeFullSystemUpdate
// (which itself requires both a deployment-level opt-in and explicit
// per-request confirmation). Any other token — including a normal
// advisory-scoped approval — is rejected here.
func BuildFullSystemUpdate(token ApprovalToken) (PatchCommand, error) {
	if !token.fullSystemUpdate {
		return PatchCommand{}, fmt.Errorf("token was not authorized for full system update (call Guard.AuthorizeFullSystemUpdate); refusing to build full-update command")
	}
	return PatchCommand{
		cmd:              "sudo dnf update -y",
		fullSystemUpdate: true,
	}, nil
}
