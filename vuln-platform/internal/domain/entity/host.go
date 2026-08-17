package entity

import "time"

// SSHAuthType defines how the platform authenticates to a managed host.
type SSHAuthType string

const (
	SSHAuthPassword SSHAuthType = "password"
	SSHAuthKey      SSHAuthType = "key"
)

// HostStatus reflects the last known reachability of a host.
type HostStatus string

const (
	HostStatusUnknown   HostStatus = "unknown"
	HostStatusReachable HostStatus = "ssh_reachable"
	HostStatusFailed    HostStatus = "ssh_failed"
	HostStatusOffline   HostStatus = "offline"
)

// Host represents a managed Linux server discovered from scanner imports
// and/or registered manually for SSH-based verification.
type Host struct {
	ID          string     `json:"id" db:"id"`
	Hostname    string     `json:"hostname" db:"hostname"`
	IPAddress   string     `json:"ip_address" db:"ip_address"`
	Environment string     `json:"environment" db:"environment"` // e.g. prod, dr, stg
	OSFamily    string     `json:"os_family" db:"os_family"`     // e.g. rhel8, rhel9
	OSVersion   string     `json:"os_version" db:"os_version"`
	Status      HostStatus `json:"status" db:"status"`

	// SSH connection details. CredentialID references an encrypted
	// credential record; the platform never stores plaintext secrets
	// on the Host record itself.
	SSHHost            string  `json:"ssh_host" db:"ssh_host"`
	SSHPort            int     `json:"ssh_port" db:"ssh_port"`
	SSHUser            string  `json:"ssh_user" db:"ssh_user"`
	JumpHostID         *string `json:"jump_host_id,omitempty" db:"jump_host_id"`
	CredentialID       string  `json:"credential_id" db:"credential_id"`
	HostKeyFingerprint string  `json:"host_key_fingerprint" db:"host_key_fingerprint"`

	Tags       map[string]string `json:"tags,omitempty" db:"-"`
	LastSeenAt *time.Time        `json:"last_seen_at,omitempty" db:"last_seen_at"`
	CreatedAt  time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at" db:"updated_at"`
}

// Credential is an encrypted-at-rest secret used for SSH authentication.
// Only ciphertext and the metadata needed to decrypt it (key ID, nonce)
// are ever persisted. Decryption happens in-memory at connection time
// and the plaintext is never logged or written to disk.
type Credential struct {
	ID              string      `json:"id" db:"id"`
	Name            string      `json:"name" db:"name"`
	AuthType        SSHAuthType `json:"auth_type" db:"auth_type"`
	EncryptedBlob   []byte      `json:"-" db:"encrypted_blob"` // AES-256-GCM ciphertext
	EncryptionKeyID string      `json:"-" db:"encryption_key_id"`
	Nonce           []byte      `json:"-" db:"nonce"`
	CreatedBy       string      `json:"created_by" db:"created_by"`
	CreatedAt       time.Time   `json:"created_at" db:"created_at"`
	RotatedAt       *time.Time  `json:"rotated_at,omitempty" db:"rotated_at"`
}
