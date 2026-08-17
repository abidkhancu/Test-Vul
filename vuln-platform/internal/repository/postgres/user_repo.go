package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

var _ repository.UserRepository = (*UserRepo)(nil)

func (r *UserRepo) Create(ctx context.Context, u *entity.User) error {
	const q = `
		INSERT INTO users (username, email, password_hash, role_id, is_active)
		VALUES ($1,$2,$3,(SELECT id FROM roles WHERE name=$4),$5)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q, u.Username, u.Email, u.PasswordHash, string(u.Role), u.IsActive).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

func (r *UserRepo) Get(ctx context.Context, id string) (*entity.User, error) {
	return r.scanOne(ctx, `
		SELECT u.id, u.username, u.email, u.password_hash, r.name, u.is_active, u.mfa_enabled,
		       u.last_login_at, u.created_at, u.updated_at
		FROM users u JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1`, id)
}

func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	return r.scanOne(ctx, `
		SELECT u.id, u.username, u.email, u.password_hash, r.name, u.is_active, u.mfa_enabled,
		       u.last_login_at, u.created_at, u.updated_at
		FROM users u JOIN roles r ON r.id = u.role_id
		WHERE u.username = $1`, username)
}

func (r *UserRepo) scanOne(ctx context.Context, q, arg string) (*entity.User, error) {
	u := &entity.User{}
	var role string
	err := r.pool.QueryRow(ctx, q, arg).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &role, &u.IsActive, &u.MFAEnabled,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.Role = entity.Role(role)
	return u, nil
}

func (r *UserRepo) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_login_at=now(), updated_at=now() WHERE id=$1`, id)
	return err
}

func (r *UserRepo) SetActive(ctx context.Context, id string, active bool) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET is_active=$1, updated_at=now() WHERE id=$2`, active, id)
	return err
}

func (r *UserRepo) SetRole(ctx context.Context, id string, role entity.Role) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET role_id = (SELECT id FROM roles WHERE name = $1), updated_at = now() WHERE id = $2`,
		string(role), id,
	)
	if err != nil {
		return fmt.Errorf("set role for user %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s not found or role %q is not a recognized role", id, role)
	}
	return nil
}

func (r *UserRepo) List(ctx context.Context, page, pageSize int) ([]*entity.User, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.password_hash, r.name, u.is_active, u.mfa_enabled,
		       u.last_login_at, u.created_at, u.updated_at
		FROM users u JOIN roles r ON r.id = u.role_id
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []*entity.User
	for rows.Next() {
		u := &entity.User{}
		var role string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &role, &u.IsActive,
			&u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		u.Role = entity.Role(role)
		out = append(out, u)
	}
	return out, total, rows.Err()
}
