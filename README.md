# bastion-vault

**Module B of the Bastion RAG Security Governance Framework**

bastion-vault is a privacy-preserving data anonymization service written in Go. It provides PII detection, multi-strategy anonymization, k-anonymity validation, RBAC-enforced access control, KMS-backed key management, and a break-glass emergency access workflow — all audit-trailed and compliance-ready for PIPA (Korea Personal Information Protection Act) and equivalent global frameworks.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Bastion Vault                            │
│                                                                  │
│  ┌─────────┐   ┌──────────────┐   ┌──────────────────────────┐  │
│  │  CLI    │   │  REST :8080  │   │     gRPC :9090           │  │
│  │ (cobra) │   │  (chi/http)  │   │     (proto stub)         │  │
│  └────┬────┘   └──────┬───────┘   └────────────┬─────────────┘  │
│       └───────────────┴────────────────────────┘                │
│                        │                                         │
│              ┌─────────┴──────────┐                             │
│              │  Anonymizer Engine │  Phase 1: PII Detection      │
│              │  (engine.go)       │  Phase 2: Strategy Apply     │
│              └─────────┬──────────┘                             │
│          ┌─────────────┼─────────────────┐                      │
│          │             │                 │                       │
│   ┌──────┴──────┐ ┌────┴──────┐ ┌───────┴────────┐             │
│   │ Classifier  │ │ K-Anon    │ │ Access Control  │             │
│   │ (PII detect)│ │ Validator │ │ (RBAC + OPA)    │             │
│   └─────────────┘ └───────────┘ └───────┬─────────┘             │
│                                         │                        │
│   ┌──────────────────┐   ┌──────────────┴──────┐                │
│   │  Break-Glass Mgr │   │  KMS Manager         │               │
│   │  (dual approval) │   │  (Local/AWS/Vault)   │               │
│   └──────────────────┘   └──────────────────────┘               │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  Audit Logger  (append-only JSONL, per-tenant signing)   │  │
│   └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
         │                    │                    │
    PostgreSQL 15         Redis 7              OPA 0.60
    (RLS per tenant)   (session cache)      (Rego policies)
```

### KMS Key Hierarchy

```
Master Key (KEK) — stored in KMS provider
├── Tenant Key (TK) — derived per tenant
│   ├── DEK (per-operation, ephemeral, 5-min TTL cache) — encrypts PII data
│   └── HMAC Key — deterministic tokenization (same input → same token)
└── Audit Key — audit log entry signing
```

---

## Features

- **PII Detection** — regex + field-name heuristics for Korean RRN, name, mobile, email, address, credit card, date of birth, salary, and more (L1–L5 sensitivity classification)
- **Multi-strategy anonymization** — deterministic tokenization, HMAC-SHA256, partial masking, generalization, range generalization, suppression, AES-256-GCM encryption
- **K-anonymity validation** — quasi-identifier grouping with automatic generalization up the SRS-defined hierarchy
- **RBAC access control** — 7-tier access level matrix (full → read → anonymized → k_anonymized → slice → aggregated → audit_log) enforced per department/role/category
- **OPA integration** — Rego policy bundle for complex attribute-based decisions
- **KMS abstraction** — pluggable backend (local file, AWS KMS, HashiCorp Vault) with DEK cache and provider failover
- **Break-glass workflow** — dual-approval emergency access (max 4 h, 15-min approval window, auto-revoke)
- **Multi-tenancy** — per-tenant key isolation, config registry, context propagation
- **Audit trail** — append-only JSONL audit log for every sensitive operation
- **Prometheus metrics** — request counts, latency histograms exposed at `/v1/metrics`
- **CLI** — `server`, `anonymize`, `detect-pii`, `classify`, `k-anon-check`, `access`, `interactive`

---

## Data Categories & K-Anonymity Thresholds

| Code  | Category           | K  | Quasi-Identifiers                               |
|-------|--------------------|----|--------------------------------------------------|
| DC-01 | Customer Data      | 5  | age_group, gender, region, membership_grade      |
| DC-02 | Manufacturing Data | 3  | product_category, factory_id, shift              |
| DC-03 | HR / Finance Data  | 10 | department, position_level, age_group, gender, tenure_years |

---

## PII Types & Anonymization Strategies

| PII Type           | Strategy                     | Reversible |
|--------------------|------------------------------|------------|
| korean_name        | deterministic_tokenization   | via registry |
| korean_rrn         | hmac_sha256                  | no         |
| korean_mobile      | partial_masking `010-****-5678` + search token | no |
| email              | deterministic_tokenization   | via registry |
| address_detail     | suppression `[REMOVED]`      | no         |
| address_city       | generalization (gu→si→province) | no      |
| credit_card        | partial_masking `1234-****-****-3456` | no |
| date_of_birth      | range_generalization (decade) | no        |
| salary             | encryption (AES-256-GCM)     | yes        |

---

## RBAC Access Matrix

| Department / Role        | DC-01 Customer    | DC-02 Manufacturing | DC-03 HR/Finance   |
|--------------------------|-------------------|---------------------|---------------------|
| marketing / manager      | full + deanonymize | read               | aggregated          |
| marketing / analyst      | k_anonymized (K=5) | k_anonymized       | aggregated          |
| manufacturing / manager  | slice (K=5)       | full                | none                |
| manufacturing / staff    | slice (K=5)       | full                | none                |
| hr / manager             | none              | none                | full + deanonymize  |
| hr / staff               | none              | none                | anonymized          |
| executive / executive    | aggregated        | aggregated          | aggregated          |
| audit / auditor          | audit_log         | audit_log           | audit_log           |

---

## Quick Start

### Prerequisites

- Go 1.21+
- Docker & Docker Compose (for the full stack)
- `openssl` (for key generation)

### 1. Generate a master key

```bash
export VAULT_KMS_LOCAL_MASTER_KEY=$(openssl rand -hex 32)
```

### 2. Run the server locally

```bash
go run ./cmd/vault server
# Listening on http://0.0.0.0:8080
```

### 3. Run with Docker Compose

```bash
VAULT_MASTER_KEY=$(openssl rand -hex 32) docker compose -f deployments/docker-compose.yml up -d
```

---

## CLI Usage

```
vault [command] [flags]

Commands:
  server          Start the REST API server
  anonymize       Anonymize records from a JSONL file
  detect-pii      Detect PII fields in a JSONL file
  classify        Classify a JSONL dataset into a data category
  k-anon-check    Validate k-anonymity of a JSONL dataset
  access          Check access level for a role against a data category
  interactive     Start an interactive REPL session
```

### detect-pii

```bash
vault detect-pii -i tests/fixtures/customer_data_samples.jsonl
```

Output:
```
╔═══════════════════════════════════════════════════════════════╗
║  Record 1 PII Detections                                      ║
╠═══════════════════════════════════════════════════════════════╣
║  name                 korean_name                    L2  95%  ║
║  rrn                  korean_rrn                     L1  95%  ║
║  mobile               korean_mobile                  L2  95%  ║
║  email                email                          L1  95%  ║
║  credit_card          credit_card                    L1  95%  ║
╚═══════════════════════════════════════════════════════════════╝
```

### classify

```bash
vault classify -i tests/fixtures/customer_data_samples.jsonl
```

### anonymize

```bash
vault anonymize -i tests/fixtures/customer_data_samples.jsonl \
  --category DC-01 \
  --requester user-123 \
  --purpose "marketing-analysis"
```

### k-anon-check

```bash
# Check only
vault k-anon-check -i tests/fixtures/customer_data_samples.jsonl -t DC-01 -k 5

# Auto-generalize until K-anonymous
vault k-anon-check -i tests/fixtures/customer_data_samples.jsonl -t DC-01 -k 5 --generalize
```

### access

```bash
vault access --department marketing --role analyst --category DC-01
```

```
╔═════════════════════════════════════════╗
║  Access Decision                        ║
╠═════════════════════════════════════════╣
║  Status       : ALLOWED                 ║
║  Access Level : k_anonymized            ║
║  Reason       : allowed by RBAC policy  ║
╚═════════════════════════════════════════╝
```

---

## REST API

Base URL: `http://localhost:8080`

All endpoints (except health/metrics) require `Authorization: Bearer <token>` and optionally `X-Tenant-ID: <tenant>`.

### Anonymize

```http
POST /v1/vault/anonymize
Content-Type: application/json

{
  "category": "DC-01",
  "records": [
    {"name": "김철수", "rrn": "850101-1234567", "mobile": "010-1234-5678"}
  ],
  "purpose": "analytics",
  "requester_id": "user-abc",
  "access_level": "anonymized"
}
```

Response:

```json
{
  "tenant_id": "default",
  "category": "DC-01",
  "records": [
    {
      "name": "TOK:abc123...",
      "rrn": "HMAC:def456...",
      "mobile": "010-****-5678",
      "mobile_search_token": "TOK:ghi789..."
    }
  ],
  "audit_id": "a1b2c3d4...",
  "metadata": {
    "record_count": 1,
    "fields_anonymized": 3,
    "strategies_applied": {
      "deterministic_tokenization": 1,
      "hmac_sha256": 1,
      "partial_masking": 1
    },
    "processed_at": "2026-05-19T10:00:00Z"
  }
}
```

### Deanonymize

```http
POST /v1/vault/deanonymize
Content-Type: application/json

{
  "category": "DC-03",
  "records": [{"salary": "ENC:..."}],
  "requester_id": "hr-manager-1",
  "justification": "payroll audit Q2"
}
```

### Classify

```http
POST /v1/vault/classify
Content-Type: application/json

{"records": [{"name": "홍길동", "salary": "72000000", "employee_id": "E001"}]}
```

### Detect PII

```http
POST /v1/vault/detect-pii
Content-Type: application/json

{"record": {"name": "김철수", "email": "kim@example.com"}}
```

### Validate K-Anonymity

```http
POST /v1/vault/k-anonymity/validate
Content-Type: application/json

{
  "records": [...],
  "category": "DC-01",
  "required_k": 5,
  "generalize": true
}
```

### Break-Glass Request

```http
POST /v1/vault/break-glass/request
Content-Type: application/json

{
  "requester_id": "on-call-engineer-1",
  "incident_id": "INC-20260519-001",
  "reason": "Production data integrity incident — customer records corrupted",
  "duration_seconds": 7200,
  "category": "DC-01"
}
```

### Break-Glass Approve

```http
POST /v1/vault/break-glass/approve
Content-Type: application/json

{"request_id": "BG-a1b2c3d4", "approver_id": "security-lead-1"}
```

Two approvals are required within 15 minutes. After the second approval, the response includes a `token` for use in subsequent anonymize/deanonymize calls via `break_glass_token`.

### Health

```http
GET /v1/health/live    # liveness probe
GET /v1/health/ready   # readiness probe
GET /v1/metrics        # Prometheus metrics
```

---

## Configuration

Configuration is loaded from `configs/vault.yaml` then overlaid with environment variables prefixed `VAULT_` (dots → underscores, e.g. `VAULT_SERVER_HTTP_PORT=9000`).

Key settings:

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `server.http_port` | `VAULT_SERVER_HTTP_PORT` | `8080` | REST listen port |
| `server.grpc_port` | `VAULT_SERVER_GRPC_PORT` | `9090` | gRPC listen port |
| `kms.provider` | `VAULT_KMS_PROVIDER` | `local` | `local` / `aws` / `vault` |
| `kms.local.master_key` | `VAULT_KMS_LOCAL_MASTER_KEY` | — | 32-byte hex AES-256 key (required) |
| `kms.dek_cache_ttl` | `VAULT_KMS_DEK_CACHE_TTL` | `5m` | DEK cache TTL |
| `opa.policy_dir` | `VAULT_OPA_POLICY_DIR` | `./policies` | Rego policy directory |
| `audit.output_dir` | `VAULT_AUDIT_OUTPUT_DIR` | `./audit-logs` | Audit log output dir |
| `audit.signing_enabled` | `VAULT_AUDIT_SIGNING_ENABLED` | `true` | Sign audit entries |
| `tenant.default_k_threshold` | `VAULT_TENANT_DEFAULT_K_THRESHOLD` | `5` | Default K |
| `log.level` | `VAULT_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `log.format` | `VAULT_LOG_FORMAT` | `json` | `json` or `text` |

See `configs/vault.yaml` for the full annotated configuration reference.

---

## Development

### Build

```bash
# Install dependencies
go mod tidy

# Build binary
make build          # → ./bin/vault

# Run tests
make test

# Run tests with coverage
make test-coverage  # → coverage.html

# Generate a master key for local dev
make gen-master-key
```

### Project Layout

```
bastion-vault/
├── cmd/vault/main.go               # CLI entrypoint (cobra)
├── internal/
│   ├── model/types.go              # Shared types (DataCategory, PIIType, etc.)
│   ├── config/config.go            # YAML + env config loading
│   ├── kms/
│   │   ├── interface.go            # KMSProvider interface
│   │   ├── local.go                # Local AES-256-GCM file-based provider
│   │   └── manager.go             # Failover + DEK cache manager
│   ├── classification/classifier.go # PII detection + category inference
│   ├── anonymizer/
│   │   ├── engine.go              # Phase 1 + Phase 2 anonymization pipeline
│   │   └── strategies/            # One file per anonymization strategy
│   ├── access/controller.go       # RBAC matrix + OPA delegation
│   ├── kanon/validator.go         # K-anonymity validation + auto-generalization
│   ├── breakglass/manager.go      # Dual-approval break-glass workflow
│   ├── tenant/isolation.go        # Per-tenant config registry + context helpers
│   ├── audit/event.go             # Append-only JSONL audit logger
│   └── server/
│       ├── rest.go                # chi router + all HTTP handlers
│       └── middleware.go          # Auth, logging, metrics, tenant middleware
├── policies/vault.rego            # OPA Rego policy bundle
├── configs/vault.yaml             # Reference configuration
├── api/proto/vault.proto          # gRPC service definition
├── deployments/
│   ├── Dockerfile                 # Multi-stage scratch image
│   ├── docker-compose.yml         # Full dev stack (Postgres, Redis, OPA, Prometheus)
│   └── k8s/deployment.yaml        # Kubernetes Deployment + HPA
└── tests/fixtures/                # Sample JSONL datasets
```

### Adding a New Strategy

1. Create `internal/anonymizer/strategies/your_strategy.go` implementing `strategies.Strategy`.
2. Add the strategy constant to `internal/model/types.go`.
3. Register it in `engine.go`'s `strategyMap`.
4. Add field policy entries in `categoryPolicies`.

### Adding a New KMS Provider

1. Implement `kms.Provider` (see `kms/interface.go`).
2. Wire it in `cmd/vault/main.go`'s `loadDeps` based on `cfg.KMS.Provider`.

---

## Testing

```bash
# Unit tests
make test

# PII detection smoke test
make detect-pii

# Classification smoke test
make classify

# K-anonymity check
make k-anon
```

Sample fixture files are in `tests/fixtures/`:
- `customer_data_samples.jsonl` — 5 DC-01 records (name, RRN, mobile, email, address, credit card, DOB)
- `hr_data_samples.jsonl` — 3 DC-03 records (employee ID, salary, evaluation grade)

---

## Deployment

### Docker

```bash
# Build image
make docker-build

# Full stack (requires VAULT_MASTER_KEY env var)
VAULT_MASTER_KEY=$(openssl rand -hex 32) make docker-up
```

Services started:
- `vault` — REST :8080, gRPC :9090
- `postgres` — PostgreSQL 15 :5432
- `redis` — Redis 7 :6379
- `opa` — OPA 0.60 :8181
- `prometheus` — Prometheus :9090

### Kubernetes

```bash
# Apply namespace and secrets
kubectl create namespace bastion
kubectl create secret generic bastion-vault-secrets \
  --namespace bastion \
  --from-literal=master-key=$(openssl rand -hex 32) \
  --from-literal=database-dsn="postgres://vault:..."

# Deploy
kubectl apply -f deployments/k8s/deployment.yaml
```

The deployment includes:
- `Deployment` with 2 replicas, liveness/readiness probes, resource limits
- `HorizontalPodAutoscaler` scaling 2–10 pods on CPU/memory
- `Service` (ClusterIP) on port 80 (HTTP) and 9090 (gRPC)
- Read-only root filesystem, non-root user, dropped capabilities

---

## Compliance

| Requirement | Implementation |
|---|---|
| PIPA §24 (pseudonymization) | Deterministic tokenization, HMAC-SHA256 |
| PIPA §28-2 (anonymization) | Suppression, generalization, masking |
| K-anonymity (SRS §3.4) | `kanon.Validator` with auto-generalization |
| Purpose limitation | `purpose` field logged in every audit event |
| Data minimization | Access levels cap field visibility by role |
| Audit trail | Append-only JSONL, per-entry timestamp + actor |
| Break-glass controls | Dual approval, 15-min window, max 4 h, auto-revoke |
| Key isolation | Per-tenant DEK / HMAC / audit key derivation |
| DEK lifecycle | 5-min cache TTL, zeroization on eviction |

### Sensitivity Levels

| Level | Classification       | Examples                  |
|-------|----------------------|---------------------------|
| L1    | Direct identifier    | RRN, SSN, email, credit card |
| L2    | Indirect identifier  | Name, phone, address      |
| L3    | Sensitive personal   | Medical records, religion |
| L4    | Quasi-identifier     | Age, gender, region       |
| L5    | Public               | Employee ID, department   |

---

## Performance Targets

| Operation              | p95 Target |
|------------------------|-----------|
| Anonymization          | < 5 ms    |
| Access control decision | < 2 ms   |
| K-anonymity validation | < 50 ms   |

---

## License

See [LICENSE](LICENSE).
