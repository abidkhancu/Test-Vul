// Mirrors internal/domain/entity.Role's capability methods on the Go
// backend (see entity/user.go: CanApprovePatches, CanRunVerification,
// CanManageUsers, CanWriteFindings). Kept as pure functions here so
// "who can do what" stays defined in one place per side, matching the
// backend's own single-source-of-truth approach — the frontend uses
// these only to decide what to *show*; the backend re-enforces every
// one of them server-side regardless of what the UI hides.
import type { Role } from "@/types/api";

export function canApprovePatches(role: Role): boolean {
  return role === "administrator" || role === "patch_approver";
}

export function canRunVerification(role: Role): boolean {
  return role === "administrator" || role === "security_analyst" || role === "operator";
}

export function canManageUsers(role: Role): boolean {
  return role === "administrator";
}

export function canWriteFindings(role: Role): boolean {
  return role === "administrator" || role === "security_analyst";
}

export function roleLabel(role: Role): string {
  switch (role) {
    case "administrator":
      return "Administrator";
    case "security_analyst":
      return "Security Analyst";
    case "operator":
      return "Operator";
    case "patch_approver":
      return "Patch Approver";
    case "viewer":
      return "Viewer";
  }
}
