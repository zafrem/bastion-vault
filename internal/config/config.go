package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration structure populated from vault.yaml + env overrides
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	KMS      KMSConfig      `mapstructure:"kms"`
	Database DatabaseConfig `mapstructure:"database"`
	Cache    CacheConfig    `mapstructure:"cache"`
	OPA      OPAConfig      `mapstructure:"opa"`
	Audit    AuditConfig    `mapstructure:"audit"`
	Tenant   TenantSettings `mapstructure:"tenant"`
	Log      LogConfig      `mapstructure:"log"`
}

type ServerConfig struct {
	HTTPPort int    `mapstructure:"http_port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	Host     string `mapstructure:"host"`
	TLSCert  string `mapstructure:"tls_cert"`
	TLSKey   string `mapstructure:"tls_key"`
}

type KMSConfig struct {
	Provider   string          `mapstructure:"provider"` // local | aws | vault
	Local      LocalKMSConfig  `mapstructure:"local"`
	AWS        AWSKMSConfig    `mapstructure:"aws"`
	Vault      VaultKMSConfig  `mapstructure:"vault"`
	DEKCacheTTL time.Duration  `mapstructure:"dek_cache_ttl"`
}

type LocalKMSConfig struct {
	KeyDir    string `mapstructure:"key_dir"`
	MasterKey string `mapstructure:"master_key"` // hex-encoded 32-byte key
}

type AWSKMSConfig struct {
	Region  string `mapstructure:"region"`
	KeyARN  string `mapstructure:"key_arn"`
	Profile string `mapstructure:"profile"`
}

type VaultKMSConfig struct {
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
	v.SetDefault("kms.provider", "local")
	v.SetDefault("kms.dek_cache_ttl", 5*time.Minute)
	v.SetDefault("kms.local.key_dir", "./keys")
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
