package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/zafrem/bastion-vault/internal/classification"
)

// Config is the root configuration structure populated from vault.yaml + env overrides
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	KMS        KMSConfig        `mapstructure:"kms"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Cache      CacheConfig      `mapstructure:"cache"`
	OPA        OPAConfig        `mapstructure:"opa"`
	Audit      AuditConfig      `mapstructure:"audit"`
	Tenant     TenantSettings   `mapstructure:"tenant"`
	Log        LogConfig        `mapstructure:"log"`
	Auth       AuthConfig       `mapstructure:"auth"`
	TokenStore TokenStoreConfig `mapstructure:"token_store"`
	RateLimit  RateLimitConfig  `mapstructure:"rate_limit"`
	Events         EventsConfig         `mapstructure:"events"`
	CloudLLM       CloudLLMConfig       `mapstructure:"cloud_llm"`
	Classification ClassificationConfig `mapstructure:"classification"`
}

// ClassificationConfig holds overrides for the PII value-pattern fallback set
// used by the classifier. Empty fields fall back to the built-in defaults
// (classification.DefaultPatternSet).
type ClassificationConfig struct {
	Patterns classification.PatternSet `mapstructure:"patterns"`
}

// CloudLLMConfig configures the Cloud LLM Connector extension (doc 21).
type CloudLLMConfig struct {
	Enabled         bool                     `mapstructure:"enabled"`
	Providers       []CloudLLMProviderConfig `mapstructure:"providers"`
	DefaultProvider string                   `mapstructure:"default_provider"`
	// TokenPattern overrides the regex used to detect Vault tokens in LLM
	// responses for de-anonymization. Empty uses cloudllm.DefaultTokenPattern.
	TokenPattern string `mapstructure:"token_pattern"`
}

// CloudLLMProviderConfig describes a single cloud LLM provider.
type CloudLLMProviderConfig struct {
	ID         string `mapstructure:"id"`
	Type       string `mapstructure:"type"`        // "openai" | "claude" | "gemini" | "custom"
	Model      string `mapstructure:"model"`
	APIKeyKMS  string `mapstructure:"api_key_kms"` // KMS reference: "env://VAR" | "plain://key"
	Endpoint   string `mapstructure:"endpoint"`    // custom providers only
	TimeoutS   int    `mapstructure:"timeout_seconds"`
	MaxRetries int    `mapstructure:"max_retries"`
}

// EventsConfig enables Foundation-standard event publishing to NATS (doc 02).
type EventsConfig struct {
	NATSUrl string `mapstructure:"nats_url"`
	Enabled bool   `mapstructure:"enabled"`
}

// TokenStoreConfig selects the persistence backend for token mappings.
type TokenStoreConfig struct {
	Driver string `mapstructure:"driver"` // "memory", "postgres", or "sqlite"
	DSN    string `mapstructure:"dsn"`    // postgres DSN or sqlite file path when driver=postgres/sqlite
}

// RateLimitConfig configures the per-IP token-bucket rate limiter.
type RateLimitConfig struct {
	Enabled bool    `mapstructure:"enabled"`
	RPS     float64 `mapstructure:"rps"`   // requests per second
	Burst   int     `mapstructure:"burst"` // token bucket burst size
}

// AuthConfig holds JWT validation settings.
type AuthConfig struct {
	JWTSecret    string `mapstructure:"jwt_secret"`
	JWTAlgorithm string `mapstructure:"jwt_algorithm"` // HS256 or RS256
	Issuer       string `mapstructure:"jwt_issuer"`
	SkipAuth     bool   `mapstructure:"skip_auth"` // dev mode only
}

type ServerConfig struct {
	HTTPPort int    `mapstructure:"http_port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	Host     string `mapstructure:"host"`
	TLSCert  string `mapstructure:"tls_cert"`
	TLSKey   string `mapstructure:"tls_key"`
}

type KMSConfig struct {
	Provider    string             `mapstructure:"provider"` // local | aws | vault
	Local       LocalKMSConfig     `mapstructure:"local"`
	AWS         AWSKMSConfig       `mapstructure:"aws"`
	HashiCorp   HashiCorpKMSConfig `mapstructure:"vault"`
	DEKCacheTTL time.Duration      `mapstructure:"dek_cache_ttl"`
}

type LocalKMSConfig struct {
	KeyDir    string `mapstructure:"key_dir"`
	MasterKey string `mapstructure:"master_key"` // hex-encoded 32-byte key
}

type AWSKMSConfig struct {
	Region      string `mapstructure:"region"`
	MasterKeyID string `mapstructure:"master_key_id"` // KMS key ID or ARN
	Profile     string `mapstructure:"profile"`
}

type HashiCorpKMSConfig struct {
	Address   string `mapstructure:"address"`
	Token     string `mapstructure:"token"`
	MountPath string `mapstructure:"mount_path"`
	KeyName   string `mapstructure:"key_name"`
}

type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type CacheConfig struct {
	Address  string        `mapstructure:"address"`
	Password string        `mapstructure:"password"`
	DB       int           `mapstructure:"db"`
	TTL      time.Duration `mapstructure:"ttl"`
}

type OPAConfig struct {
	PolicyDir    string `mapstructure:"policy_dir"`
	BundleServer string `mapstructure:"bundle_server"`
	DecisionLog  string `mapstructure:"decision_log"`
}

type AuditConfig struct {
	OutputDir      string `mapstructure:"output_dir"`
	SigningEnabled bool   `mapstructure:"signing_enabled"`
	Retention      int    `mapstructure:"retention_days"`
}

type TenantSettings struct {
	DefaultKThreshold int `mapstructure:"default_k_threshold"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"` // json | text
}

// Load reads configuration from the given file path, then overlays environment variables.
// Environment variables are mapped as VAULT_SERVER_HTTP_PORT → server.http_port.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	v.SetDefault("server.http_port", 8080)
	v.SetDefault("server.grpc_port", 9090)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("auth.jwt_secret", "change-me-in-production")
	v.SetDefault("auth.jwt_algorithm", "HS256")
	v.SetDefault("auth.jwt_issuer", "bastion")
	v.SetDefault("auth.skip_auth", false)
	v.SetDefault("kms.provider", "local")
	v.SetDefault("kms.dek_cache_ttl", 5*time.Minute)
	v.SetDefault("kms.local.key_dir", "./keys")
	v.SetDefault("kms.vault.mount_path", "transit")
	v.SetDefault("token_store.driver", "memory")
	v.SetDefault("rate_limit.enabled", false)
	v.SetDefault("rate_limit.rps", 100)
	v.SetDefault("rate_limit.burst", 200)
	v.SetDefault("opa.policy_dir", "./policies")
	v.SetDefault("audit.output_dir", "./audit-logs")
	v.SetDefault("audit.signing_enabled", true)
	v.SetDefault("audit.retention_days", 365)
	v.SetDefault("tenant.default_k_threshold", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("vault")
		v.SetConfigType("yaml")
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
	}

	v.SetEnvPrefix("VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	return &cfg, nil
}
