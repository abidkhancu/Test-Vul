package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool}
}

var _ repository.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

func (r *RefreshTokenRepo) Create(ctx context.Context, t *entity.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1,$2,$3)
		RETURNING id, created_at`
	return r.pool.QueryRow(ctx, q, t.UserID, t.TokenHash, t.ExpiresAt).Scan(&t.ID, &t.CreatedAt)
}

func (r *RefreshTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
		FROM refresh_tokens WHERE token_hash = $1`
	t := &entity.RefreshToken{}
	err := r.pool.QueryRow(ctx, q, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return t, nil
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return err
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}
