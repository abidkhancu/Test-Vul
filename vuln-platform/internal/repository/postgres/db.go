// Package postgres implements the outbound repository ports defined
// in internal/domain/repository using pgx v5's connection pool. This
// is the only package in the codebase that should import pgx
// directly, per hexagonal architecture: swapping the storage engine
// later means replacing this package, not touching usecase/domain
// code.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ubank/vuln-platform/internal/config"
)

// NewPool builds a pgx connection pool tuned from config. Callers
// should defer pool.Close() at application shutdown.
func NewPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Name,
		cfg.Database.User, cfg.Database.Password, cfg.Database.SSLMode,
	)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	poolCfg.MaxConns = cfg.Database.MaxConns
	poolCfg.MinConns = cfg.Database.MinConns
	poolCfg.MaxConnLifetime = cfg.Database.ConnMaxLifetime
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
