package config

import "testing"

// Deployments configure the token store through the environment, with or without those keys in a config file.
func TestLoad_TokenStoreFromEnvironment(t *testing.T) {
	t.Chdir(t.TempDir()) // no configs/vault.yaml here
	t.Setenv("VAULT_TOKEN_STORE_DRIVER", "postgres")
	t.Setenv("VAULT_TOKEN_STORE_DSN", "postgres://example/db")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenStore.Driver != "postgres" || cfg.TokenStore.DSN != "postgres://example/db" {
		t.Errorf("environment not applied: %+v", cfg.TokenStore)
	}
}
