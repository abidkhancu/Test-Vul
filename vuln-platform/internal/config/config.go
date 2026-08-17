// Package config centralizes configuration loading via viper, reading
// from (in increasing precedence order) defaults, a config file, and
// environment variables. Secrets (DB password, JWT signing key,
// credential-encryption master key) are expected via environment
// variables or a mounted secrets file — never committed to the config
// file itself.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Env string `mapstructure:"env"` // dev | staging | prod

	HTTP struct {
		Port            int           `mapstructure:"port"`
		ReadTimeout     time.Duration `mapstructure:"read_timeout"`
		WriteTimeout    time.Duration `mapstructure:"write_timeout"`
		ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	} `mapstructure:"http"`

	Database struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		Name            string        `mapstructure:"name"`
		User            string        `mapstructure:"user"`
		Password        string        `mapstructure:"password"` // env: VULN_DATABASE_PASSWORD
		SSLMode         string        `mapstructure:"ssl_mode"`
		MaxConns        int32         `mapstructure:"max_conns"`
		MinConns        int32         `mapstructure:"min_conns"`
		ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	} `mapstructure:"database"`

	Redis struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"` // env: VULN_REDIS_PASSWORD
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	Auth struct {
		JWTSigningKey           string        `mapstructure:"jwt_signing_key"` // env: VULN_AUTH_JWT_SIGNING_KEY
		AccessTokenTTL          time.Duration `mapstructure:"access_token_ttl"`
		RefreshTokenTTL         time.Duration `mapstructure:"refresh_token_ttl"`
		CredentialEncryptionKey string        `mapstructure:"credential_encryption_key"` // env: VULN_AUTH_CREDENTIAL_ENCRYPTION_KEY, 32 bytes for AES-256
	} `mapstructure:"auth"`

	SSH struct {
		ConnectTimeout     time.Duration `mapstructure:"connect_timeout"`
		CommandTimeout     time.Duration `mapstructure:"command_timeout"`
		MaxConcurrent      int           `mapstructure:"max_concurrent"` // global cap across all verification jobs
		MaxRetries         int           `mapstructure:"max_retries"`
		StrictHostKeyCheck bool          `mapstructure:"strict_host_key_check"`
	} `mapstructure:"ssh"`

	Import struct {
		WorkerConcurrency int `mapstructure:"worker_concurrency"`
		QueueDepth        int `mapstructure:"queue_depth"`
		MaxFileSizeMB     int `mapstructure:"max_file_size_mb"`
	} `mapstructure:"import"`

	Safety struct {
		// AllowFullSystemUpdate gates the "-y" / full-update path
		// described in the spec's read-only-safety section. This
		// must default to false and should require a second,
		// explicit flag at the call site even when true — it is not
		// meant to be flipped lightly.
		AllowFullSystemUpdate bool `mapstructure:"allow_full_system_update"`
	} `mapstructure:"safety"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/vuln-platform")
	}

	setDefaults(v)

	v.SetEnvPrefix("VULN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
		// Missing config file is fine — defaults + env vars can carry
		// a container deployment entirely.
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("env", "dev")

	v.SetDefault("http.port", 8080)
	v.SetDefault("http.read_timeout", 15*time.Second)
	v.SetDefault("http.write_timeout", 30*time.Second)
	v.SetDefault("http.shutdown_timeout", 15*time.Second)

	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "vuln_platform")
	v.SetDefault("database.user", "vuln_platform")
	v.SetDefault("database.ssl_mode", "require")
	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.min_conns", 5)
	v.SetDefault("database.conn_max_lifetime", time.Hour)

	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)

	v.SetDefault("auth.access_token_ttl", 15*time.Minute)
	v.SetDefault("auth.refresh_token_ttl", 7*24*time.Hour)

	v.SetDefault("ssh.connect_timeout", 10*time.Second)
	v.SetDefault("ssh.command_timeout", 60*time.Second)
	v.SetDefault("ssh.max_concurrent", 50)
	v.SetDefault("ssh.max_retries", 2)
	v.SetDefault("ssh.strict_host_key_check", true)

	v.SetDefault("import.worker_concurrency", 8)
	v.SetDefault("import.queue_depth", 200)
	v.SetDefault("import.max_file_size_mb", 200)

	v.SetDefault("safety.allow_full_system_update", false)
}

func (c *Config) validate() error {
	if c.Env == "prod" {
		if c.Auth.JWTSigningKey == "" {
			return fmt.Errorf("auth.jwt_signing_key (VULN_AUTH_JWT_SIGNING_KEY) is required in prod")
		}
		if len(c.Auth.CredentialEncryptionKey) != 32 {
			return fmt.Errorf("auth.credential_encryption_key must be exactly 32 bytes for AES-256 in prod")
		}
		if c.Database.SSLMode == "disable" {
			return fmt.Errorf("database.ssl_mode must not be 'disable' in prod")
		}
	}
	return nil
}
