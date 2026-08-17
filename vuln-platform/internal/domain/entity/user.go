package entity

import "time"

// Role mirrors the `roles` table: fixed, small enum rather than
// free-text, so RBAC checks are exhaustive switch statements the
// compiler can help verify rather than string comparisons scattered
// through handlers.
type Role string

const (
	RoleAdministrator   Role = "administrator"
	RoleSecurityAnalyst Role = "security_analyst"
	RoleOperator        Role = "operator"
	RolePatchApprover   Role = "patch_approver"
	RoleViewer          Role = "viewer"
)

// CanApprovePatches reports whether this role is permitted to approve
// or reject remediation tasks and trigger patch execution. Kept as a
// method on Role (rather than inline checks at each call site) so
// there's exactly one place that defines "who can approve patches."
func (r Role) CanApprovePatches() bool {
	return r == RoleAdministrator || r == RolePatchApprover
}

// CanRunVerification reports whether this role may trigger read-only
// SSH verification.
func (r Role) CanRunVerification() bool {
	switch r {
	case RoleAdministrator, RoleSecurityAnalyst, RoleOperator:
		return true
	default:
		return false
	}
}

// CanManageUsers reports whether this role may create/modify users
// and role assignments.
func (r Role) CanManageUsers() bool {
	return r == RoleAdministrator
}

// CanWriteFindings reports whether this role may import scanner
// reports and modify finding/remediation records (as opposed to
// read-only dashboard access).
func (r Role) CanWriteFindings() bool {
	switch r {
	case RoleAdministrator, RoleSecurityAnalyst:
		return true
	default:
		return false
	}
}

type User struct {
	ID           string     `json:"id" db:"id"`
	Username     string     `json:"username" db:"username"`
	Email        string     `json:"email" db:"email"`
	PasswordHash string     `json:"-" db:"password_hash"`
	Role         Role       `json:"role" db:"role_name"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	MFAEnabled   bool       `json:"mfa_enabled" db:"mfa_enabled"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

// RefreshToken tracks issued refresh tokens so they can be revoked
// (logout, password change, admin-forced revocation) rather than
// remaining valid until natural expiry no matter what.
type RefreshToken struct {
	ID        string     `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`
	TokenHash string     `json:"-" db:"token_hash"` // sha256 of the actual token; raw token is never stored
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}
