package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type CredentialRepo struct {
	pool *pgxpool.Pool
}

func NewCredentialRepo(pool *pgxpool.Pool) *CredentialRepo {
	return &CredentialRepo{pool: pool}
}

var _ repository.CredentialRepository = (*CredentialRepo)(nil)

// Create persists ciphertext only. Callers must have already run the
// plaintext through crypto.CredentialCipher.Encrypt — this repository
// has no knowledge of plaintext and will happily store garbage if
// handed unencrypted bytes, so the encryption step is the caller's
// (usecase-layer) responsibility, not enforced here.
func (r *CredentialRepo) Create(ctx context.Context, c *entity.Credential) error {
	const q = `
		INSERT INTO credentials (name, auth_type, encrypted_blob, encryption_key_id, nonce, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, created_at`
	return r.pool.QueryRow(ctx, q, c.Name, string(c.AuthType), c.EncryptedBlob, c.EncryptionKeyID, c.Nonce, c.CreatedBy).
		Scan(&c.ID, &c.CreatedAt)
}

func (r *CredentialRepo) Get(ctx context.Context, id string) (*entity.Credential, error) {
	const q = `
		SELECT id, name, auth_type, encrypted_blob, encryption_key_id, nonce, created_by, created_at, rotated_at
		FROM credentials WHERE id=$1`
	c := &entity.Credential{}
	var authType string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.Name, &authType, &c.EncryptedBlob, &c.EncryptionKeyID, &c.Nonce,
		&c.CreatedBy, &c.CreatedAt, &c.RotatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get credential %s: %w", id, err)
	}
	c.AuthType = entity.SSHAuthType(authType)
	return c, nil
}
