// Package config centralizes configuration loading purely from
// environment variables, prefixed VULN_ (e.g. VULN_DATABASE_HOST,
// VULN_AUTH_JWT_SIGNING_KEY). Secrets (DB password, JWT signing key,
// credential-encryption master key) are expected via environment
// variables or a mounted secrets file — never committed to source.
//
// This intentionally has zero third-party dependencies. An earlier
// version of this package used viper for YAML-file + env-var config
// merging, but every real deployment path in this repo (docker-compose,
// the plain Kubernetes manifests, and the Helm chart) already injects
// configuration purely as environment variables via ConfigMap/Secret —
// so a YAML config file was dead weight that existed only in theory,
// while its dependency chain (viper -> gopkg.in/yaml.v3,
// gopkg.in/ini.v1, and several others) was the single largest source
// of third-party surface area in this module. Dropping it removes
// that whole chain for one field's worth of actual behavior difference.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env string // dev | staging | prod

	HTTP struct {
		Port            int
		ReadTimeout     time.Duration
		WriteTimeout    time.Duration
		ShutdownTimeout time.Duration
	}

	Database struct {
		Host            string
		Port            int
		Name            string
		User            string
		Password        string // env: VULN_DATABASE_PASSWORD
		SSLMode         string
		MaxConns        int32
		MinConns        int32
		ConnMaxLifetime time.Duration
	}

	Redis struct {
		Addr     string
		Password string // env: VULN_REDIS_PASSWORD
		DB       int
	}

	Auth struct {
		JWTSigningKey           string // env: VULN_AUTH_JWT_SIGNING_KEY
		AccessTokenTTL          time.Duration
		RefreshTokenTTL         time.Duration
		CredentialEncryptionKey string // env: VULN_AUTH_CREDENTIAL_ENCRYPTION_KEY, must be exactly 32 bytes for AES-256
	}

	SSH struct {
		ConnectTimeout     time.Duration
		CommandTimeout     time.Duration
		MaxConcurrent      int // global cap across all verification jobs
		MaxRetries         int
		StrictHostKeyCheck bool
	}

	Import struct {
		WorkerConcurrency int
		QueueDepth        int
		MaxFileSizeMB     int
	}

	Safety struct {
		// AllowFullSystemUpdate gates the "-y" / full-update path
		// described in the spec's read-only-safety section. This
		// must default to false and should require a second,
		// explicit flag at the call site even when true — it is not
		// meant to be flipped lightly.
		AllowFullSystemUpdate bool
	}
}

// Load reads configuration purely from VULN_-prefixed environment
// variables, applying defaults for anything unset. There is no config
// file to look for — the configPath parameter from earlier versions
// of this function is gone; see the package doc comment for why.
func Load() (*Config, error) {
	cfg := &Config{}

	cfg.Env = getEnv("VULN_ENV", "dev")

	cfg.HTTP.Port = getEnvInt("VULN_HTTP_PORT", 8080)
	cfg.HTTP.ReadTimeout = getEnvDuration("VULN_HTTP_READ_TIMEOUT", 15*time.Second)
	cfg.HTTP.WriteTimeout = getEnvDuration("VULN_HTTP_WRITE_TIMEOUT", 30*time.Second)
	cfg.HTTP.ShutdownTimeout = getEnvDuration("VULN_HTTP_SHUTDOWN_TIMEOUT", 15*time.Second)

	cfg.Database.Host = getEnv("VULN_DATABASE_HOST", "localhost")
	cfg.Database.Port = getEnvInt("VULN_DATABASE_PORT", 5432)
	cfg.Database.Name = getEnv("VULN_DATABASE_NAME", "vuln_platform")
	cfg.Database.User = getEnv("VULN_DATABASE_USER", "vuln_platform")
	cfg.Database.Password = getEnv("VULN_DATABASE_PASSWORD", "")
	cfg.Database.SSLMode = getEnv("VULN_DATABASE_SSL_MODE", "require")
	cfg.Database.MaxConns = int32(getEnvInt("VULN_DATABASE_MAX_CONNS", 25))
	cfg.Database.MinConns = int32(getEnvInt("VULN_DATABASE_MIN_CONNS", 5))
	cfg.Database.ConnMaxLifetime = getEnvDuration("VULN_DATABASE_CONN_MAX_LIFETIME", time.Hour)

	cfg.Redis.Addr = getEnv("VULN_REDIS_ADDR", "localhost:6379")
	cfg.Redis.Password = getEnv("VULN_REDIS_PASSWORD", "")
	cfg.Redis.DB = getEnvInt("VULN_REDIS_DB", 0)

	cfg.Auth.JWTSigningKey = getEnv("VULN_AUTH_JWT_SIGNING_KEY", "")
	cfg.Auth.AccessTokenTTL = getEnvDuration("VULN_AUTH_ACCESS_TOKEN_TTL", 15*time.Minute)
	cfg.Auth.RefreshTokenTTL = getEnvDuration("VULN_AUTH_REFRESH_TOKEN_TTL", 7*24*time.Hour)
	cfg.Auth.CredentialEncryptionKey = getEnv("VULN_AUTH_CREDENTIAL_ENCRYPTION_KEY", "")

	cfg.SSH.ConnectTimeout = getEnvDuration("VULN_SSH_CONNECT_TIMEOUT", 10*time.Second)
	cfg.SSH.CommandTimeout = getEnvDuration("VULN_SSH_COMMAND_TIMEOUT", 60*time.Second)
	cfg.SSH.MaxConcurrent = getEnvInt("VULN_SSH_MAX_CONCURRENT", 50)
	cfg.SSH.MaxRetries = getEnvInt("VULN_SSH_MAX_RETRIES", 2)
	cfg.SSH.StrictHostKeyCheck = getEnvBool("VULN_SSH_STRICT_HOST_KEY_CHECK", true)

	cfg.Import.WorkerConcurrency = getEnvInt("VULN_IMPORT_WORKER_CONCURRENCY", 8)
	cfg.Import.QueueDepth = getEnvInt("VULN_IMPORT_QUEUE_DEPTH", 200)
	cfg.Import.MaxFileSizeMB = getEnvInt("VULN_IMPORT_MAX_FILE_SIZE_MB", 200)

	cfg.Safety.AllowFullSystemUpdate = getEnvBool("VULN_SAFETY_ALLOW_FULL_SYSTEM_UPDATE", false)

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Env == "prod" {
		if c.Auth.JWTSigningKey == "" {
			return fmt.Errorf("VULN_AUTH_JWT_SIGNING_KEY is required in prod")
		}
		if len(c.Auth.CredentialEncryptionKey) != 32 {
			return fmt.Errorf("VULN_AUTH_CREDENTIAL_ENCRYPTION_KEY must be exactly 32 bytes for AES-256 in prod")
		}
		if c.Database.SSLMode == "disable" {
			return fmt.Errorf("VULN_DATABASE_SSL_MODE must not be 'disable' in prod")
		}
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
