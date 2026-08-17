package repository

import (
	"context"

	"github.com/ubank/vuln-platform/internal/domain/entity"
)

type UserRepository interface {
	Create(ctx context.Context, u *entity.User) error
	Get(ctx context.Context, id string) (*entity.User, error)
	GetByUsername(ctx context.Context, username string) (*entity.User, error)
	UpdateLastLogin(ctx context.Context, id string) error
	SetActive(ctx context.Context, id string, active bool) error
	SetRole(ctx context.Context, id string, role entity.Role) error
	List(ctx context.Context, page, pageSize int) ([]*entity.User, int, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, t *entity.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForUser(ctx context.Context, userID string) error
}
