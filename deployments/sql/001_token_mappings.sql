-- Token → original mappings. `original` holds ciphertext: Vault encrypts it before writing.
CREATE TABLE IF NOT EXISTS token_mappings (
  token      TEXT NOT NULL,
  tenant_id  TEXT NOT NULL,
  original   BYTEA NOT NULL,
  pii_type   TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (token, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_token_mappings_tenant ON token_mappings(tenant_id);
