# Vault — Deterministic De-identification

**Module:** Vault (`internal/anonymizer/`, `internal/kms/`)
**Version:** 3.0
**Last updated:** 2026-05-30

---

## Overview

De-identification in Vault is **deterministic**: the same input value always produces the same output token, given the same key material. This property is essential in a RAG system because:

- Vector search requires matching tokens across documents (a non-deterministic token would break retrieval)
- Joins on anonymized fields (e.g., linking a customer order to a service ticket by tokenized customer ID) remain valid
- Vault Phase-2 reversal works by registry lookup, not by trying all possible outputs

The trade-off is that determinism enables frequency analysis attacks on low-cardinality fields (e.g., gender). To mitigate this, high-sensitivity identifying fields use HMAC-SHA256 (one-way, not reversible) while lower-risk fields use reversible deterministic tokenization.

---

## Strategy interface

All anonymization techniques implement a single `Strategy` interface:

```go
// internal/anonymizer/strategies/strategy.go

type Strategy interface {
    // Apply transforms a plaintext value into its anonymized form.
    Apply(ctx context.Context, value string, params Params) (string, error)

    // Reverse undoes Apply for reversible strategies.
    // Returns ErrNotReversible for one-way transformations.
    Reverse(ctx context.Context, value string, params Params) (string, error)

    // Name returns the canonical strategy identifier used in audit logs.
    Name() string

    // Reversible reports whether this strategy can reconstruct the original value.
    Reversible() bool
}

// ErrNotReversible is the sentinel error returned by one-way strategies.
type ErrNotReversible struct{ Strategy string }

func (e ErrNotReversible) Error() string {
    return e.Strategy + ": strategy is not reversible"
}
```

### `Params` — key material bundle

Every `Apply` and `Reverse` call receives a `Params` struct that bundles all key material and field context. The strategy never fetches keys itself; the engine resolves them from KMS and injects them:

```go
// internal/anonymizer/strategies/strategy.go

type Params struct {
    HMACKey             []byte // 32-byte key for HMAC and tokenization strategies
    EncryptionKey       []byte // 32-byte AES-256 key for the encryption strategy
    MaskPattern         string // override for partial masking (e.g. "010-****-{last4}")
    GeneralizationLevel int    // 0=finest, higher=coarser
    Domain              string // extra context (e.g. email domain to preserve)
    FieldHint           string // field name passed to range-generalization for switch
    TenantID            string // scopes token registry lookups
}
```

---

## Strategy catalogue

Eight strategies are registered in the engine. Each is described with its full implementation and the field types it is assigned to.

---

### 1. `deterministic_tokenization`

**Reversible:** yes (requires token registry)
**Used for:** Korean names, email addresses, employee IDs, worker IDs

HMAC-SHA256 on the raw value; the digest is base64url-encoded and truncated to 22 characters. The `TOK:` prefix makes tokenized values distinguishable from original values in downstream processing.

```go
// internal/anonymizer/strategies/tokenization.go

func (s *TokenizationStrategy) Apply(ctx context.Context, value string, p Params) (string, error) {
    if len(p.HMACKey) == 0 {
        return "", fmt.Errorf("tokenization: HMAC key required")
    }

    // HMAC-SHA256: deterministic because the key is fixed per tenant×category.
    // The same name "홍길동" always produces the same TOK: for the same tenant,
    // but a different TOK: for a different tenant (different HMACKey).
    mac := hmac.New(sha256.New, p.HMACKey)
    mac.Write([]byte(value))
    sum := mac.Sum(nil)

    // URL-safe base64 without padding; truncate to 22 chars (128-bit prefix).
    token := base64.RawURLEncoding.EncodeToString(sum)
    if len(token) > 22 {
        token = token[:22]
    }
    tok := "TOK:" + token  // e.g. "TOK:RjIzbTYxdmVBcFVNVVhi"

    // Persist the token→original mapping so Phase 2 can reverse it.
    // Store failure is non-fatal: the token is returned even if persistence fails.
    if s.store != nil {
        entry := tokendb.Entry{
            Token:     token,        // raw 22-char value (no prefix)
            Original:  value,        // plaintext
            TenantID:  p.TenantID,   // scopes the registry entry
            PIIType:   p.FieldHint,  // e.g. "name", "email"
            CreatedAt: time.Now().UTC(),
        }
        _ = s.store.Put(ctx, entry)
    }

    return tok, nil
}

// Reverse strips the "TOK:" prefix and looks up the original in the registry.
func (s *TokenizationStrategy) Reverse(ctx context.Context, value string, p Params) (string, error) {
    if s.store == nil {
        return "", ErrNotReversible{Strategy: s.Name()}
    }
    tok := value
    if strings.HasPrefix(tok, "TOK:") {
        tok = tok[4:]  // strip prefix before registry lookup
    }
    entry, err := s.store.Get(ctx, tok, p.TenantID)
    if err != nil {
        return "", fmt.Errorf("tokenization: store lookup: %w", err)
    }
    if entry == nil {
        return "", fmt.Errorf("tokenization: token not found in registry")
    }
    return entry.Original, nil
}
```

`TokenizationStrategy` becomes reversible only when a `tokendb.Store` is attached:

```go
func (s *TokenizationStrategy) Reversible() bool { return s.store != nil }
```

---

### 2. `hmac_sha256`

**Reversible:** no
**Used for:** Korean Resident Registration Number (RRN)

One-way HMAC-SHA256 with the `HMAC:` prefix. The RRN is the highest-sensitivity field (L1 direct identifier); reversibility is never permitted. An auditor can verify that a given RRN maps to a specific `HMAC:` value, but cannot go backwards.

```go
// internal/anonymizer/strategies/hmac.go

func (s *HMACStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
    if len(p.HMACKey) == 0 {
        return "", fmt.Errorf("hmac_sha256: HMAC key required")
    }
    mac := hmac.New(sha256.New, p.HMACKey)
    mac.Write([]byte(value))
    // Full 64-hex output — no truncation, because RRN frequency analysis
    // requires the full entropy of a 256-bit digest to resist preimage attacks.
    return "HMAC:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *HMACStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
    return "", ErrNotReversible{Strategy: s.Name()}
}
```

**Why HMAC vs plain hash:** A plain SHA-256 of an RRN is rainbow-table-attackable because the RRN format is structured (YYMMDD-XXXXXXX with known constraints). HMAC with a per-tenant key prevents offline dictionary attacks even if the `HMAC:` values are leaked.

---

### 3. `partial_masking`

**Reversible:** no
**Used for:** Korean mobile numbers, credit card numbers

Preserves a usable prefix and suffix for display while hiding the middle portion. For fields with `maskForSearch: true` (Korean mobile), the engine also produces a deterministic search token alongside the masked display value.

```go
// internal/anonymizer/strategies/masking.go

func (s *MaskingStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
    switch {
    case isMobile(value):
        return maskMobile(value), nil     // "010-****-5678"
    case isCreditCard(value):
        return maskCreditCard(value), nil // "1234-****-****-3456"
    default:
        return maskGeneric(value, p.MaskPattern), nil
    }
}

// maskMobile: strips non-digits, preserves first 3 and last 4 digits.
// "010-1234-5678" → "010-****-5678"
func maskMobile(v string) string {
    digits := stripNonDigits(v)
    if len(digits) < 10 {
        return strings.Repeat("*", utf8.RuneCountInString(v))
    }
    return digits[:3] + "-****-" + digits[len(digits)-4:]
}

// maskCreditCard: preserves first 4 and last 4 digits.
// "1234567890123456" → "1234-****-****-3456"
func maskCreditCard(v string) string {
    digits := stripNonDigits(v)
    if len(digits) < 8 {
        return strings.Repeat("*", utf8.RuneCountInString(v))
    }
    return digits[:4] + "-****-****-" + digits[len(digits)-4:]
}

// maskGeneric: keeps first and last quarter of runes; masks the middle.
// "홍길동" (3 runes) → "홍*동"
func maskGeneric(v, pattern string) string {
    if pattern != "" {
        return pattern // caller-supplied format wins
    }
    runes := []rune(v)
    n := len(runes)
    if n <= 2 {
        return strings.Repeat("*", n)
    }
    keep := n / 4
    if keep < 1 {
        keep = 1
    }
    masked := make([]rune, n)
    copy(masked, runes[:keep])
    for i := keep; i < n-keep; i++ {
        masked[i] = '*'
    }
    copy(masked[n-keep:], runes[n-keep:])
    return string(masked)
}
```

---

### 4. `encryption` (AES-256-GCM)

**Reversible:** yes (with DEK)
**Used for:** salary data (HR-Finance category)

AES-256-GCM with a random 12-byte nonce prepended to the ciphertext. The nonce is part of the stored value, so `Reverse` can extract it without a separate column. The `ENC:` prefix allows `Deanonymize` to distinguish encrypted fields from already-plain fields during reversal.

```go
// internal/anonymizer/strategies/encryption.go

func (s *EncryptionStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
    if len(p.EncryptionKey) == 0 {
        return "", fmt.Errorf("encryption: key required")
    }
    ct, err := gcmEncrypt(p.EncryptionKey, []byte(value))
    if err != nil {
        return "", fmt.Errorf("encryption: %w", err)
    }
    return "ENC:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// gcmEncrypt: nonce is prepended to ciphertext in the returned slice.
// Layout of returned bytes: [nonce (12 bytes)] [ciphertext + 16-byte GCM tag]
func gcmEncrypt(key, plaintext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    gcm, _   := cipher.NewGCM(block)

    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    // gcm.Seal(dst, nonce, plaintext, additionalData)
    // Prepends nonce to the output slice — nonce is recoverable at decrypt time.
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *EncryptionStrategy) Reverse(_ context.Context, value string, p Params) (string, error) {
    const prefix = "ENC:"
    ct, _ := base64.RawURLEncoding.DecodeString(value[len(prefix):])
    pt, err := gcmDecrypt(p.EncryptionKey, ct)
    if err != nil {
        return "", fmt.Errorf("encryption: %w", err)
    }
    return string(pt), nil
}

func gcmDecrypt(key, ciphertext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    gcm, _   := cipher.NewGCM(block)
    // Split nonce from ciphertext using the GCM nonce size (12 bytes).
    nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, nil) // returns error if tag verification fails
}
```

The GCM authentication tag means any ciphertext modification (bit flip, truncation) causes `gcmDecrypt` to return an error, providing integrity protection in addition to confidentiality.

---

### 5. `generalization`

**Reversible:** no
**Used for:** address city (Korean address hierarchy)

Removes the finest-grained address component per generalization level. Level 1 strips `동/로/길` (neighbourhood), level 2 strips `구/군` (district), level 3 strips `시` (city).

```go
// internal/anonymizer/strategies/generalization.go

func generalizeRegion(value string, level int) string {
    parts := strings.Fields(value) // split on whitespace
    if len(parts) == 0 {
        return ""
    }
    // Level 1: strip 동/로/길 (neighbourhood suffix)
    if level >= 1 {
        last := parts[len(parts)-1]
        if strings.HasSuffix(last, "동") || strings.HasSuffix(last, "로") || strings.HasSuffix(last, "길") {
            parts = parts[:len(parts)-1]
        }
    }
    // Level 2: strip 구/군 (district suffix)
    if level >= 2 && len(parts) > 0 {
        last := parts[len(parts)-1]
        if strings.HasSuffix(last, "구") || strings.HasSuffix(last, "군") {
            parts = parts[:len(parts)-1]
        }
    }
    // Level 3: strip 시 (city suffix)
    if level >= 3 && len(parts) > 0 {
        last := parts[len(parts)-1]
        if strings.HasSuffix(last, "시") {
            parts = parts[:len(parts)-1]
        }
    }
    return strings.Join(parts, " ")
}
```

**Example:** `"서울특별시 강남구 역삼동"` →
- Level 1: `"서울특별시 강남구"` (역삼동 removed)
- Level 2: `"서울특별시"` (강남구 also removed)

---

### 6. `range_generalization`

**Reversible:** no
**Used for:** date of birth, age, salary

Dispatches on `FieldHint` to apply the semantically correct range bracket:

```go
// internal/anonymizer/strategies/generalization.go

func (s *RangeGeneralizationStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
    hint := strings.ToLower(p.FieldHint)
    switch {
    case strings.Contains(hint, "birth") || strings.Contains(hint, "dob") || strings.Contains(hint, "생년"):
        return generalizeDateToDecade(value)    // "1985-03-15" → "1980s"
    case strings.Contains(hint, "age") || strings.Contains(hint, "나이"):
        return generalizeAge(value, p.GeneralizationLevel) // 32 → "30-34" or "30대"
    case strings.Contains(hint, "salary") || strings.Contains(hint, "급여"):
        return generalizeSalaryRange(value, p.GeneralizationLevel) // 55000000 → "5000-5500만원"
    default:
        return generalizeNumericRange(value, 10), nil // generic 10-unit buckets
    }
}

// generalizeDateToDecade: parses YYYY and maps to decade string.
// "1985-03-15" → decade=1980 → "1980s"
func generalizeDateToDecade(value string) (string, error) {
    value = strings.ReplaceAll(value, "/", "-")
    parts := strings.Split(value, "-")
    year, _ := strconv.Atoi(parts[0][:4])
    decade := (year / 10) * 10
    return fmt.Sprintf("%ds", decade), nil
}

// generalizeSalaryRange: treats value as KRW; normalises to 만원 (÷10,000).
// Level 3 produces named bands: "3000만원 미만" / "3000-5000만원" / etc.
func generalizeSalaryRange(value string, level int) (string, error) {
    cleaned := strings.Map(func(r rune) rune {
        if r >= '0' && r <= '9' { return r }
        return -1
    }, value)
    n, _ := strconv.ParseInt(cleaned, 10, 64)
    if n > 10000 { n = n / 10000 } // convert to 만원 units

    var step int64 = 500 // 500만원 brackets at level 1
    if level >= 2 { step = 1000 }
    if level >= 3 {
        switch {
        case n < 3000: return "3000만원 미만", nil
        case n < 5000: return "3000-5000만원", nil
        case n < 8000: return "5000-8000만원", nil
        default:       return "8000만원 이상", nil
        }
    }
    low := (n / step) * step
    return fmt.Sprintf("%d-%d만원", low, low+step), nil
}
```

---

### 7. `suppression`

**Reversible:** no
**Used for:** address detail (full street address)

Replaces the entire field value with `[REMOVED]`. No partial information is preserved. Used for fields where even a single character leaking (e.g., the start of a street address) could narrow re-identification.

```go
// internal/anonymizer/strategies/suppression.go

const suppressionPlaceholder = "[REMOVED]"

func (s *SuppressionStrategy) Apply(_ context.Context, _ string, _ Params) (string, error) {
    return suppressionPlaceholder, nil // value is not even read
}
```

---

## Strategy assignment table (`categoryPolicies`)

The engine hardcodes the strategy for each PII type within each data category. The table implements the SRS §3.3 PII Strategy Table:

```go
// internal/anonymizer/engine.go

var categoryPolicies = map[model.DataCategory][]fieldPolicy{
    model.CategoryCustomer: { // DC-01
        {piiType: model.PIIKoreanName,    strategy: model.StrategyDeterministicTokenization},
        {piiType: model.PIIKoreanRRN,     strategy: model.StrategyHMACSHA256},
        {piiType: model.PIIKoreanMobile,  strategy: model.StrategyPartialMasking, maskForSearch: true},
        {piiType: model.PIIEmail,         strategy: model.StrategyDeterministicTokenization},
        {piiType: model.PIIAddressDetail, strategy: model.StrategySuppression},
        {piiType: model.PIIAddressCity,   strategy: model.StrategyGeneralization},
        {piiType: model.PIICreditCard,    strategy: model.StrategyPartialMasking},
        {piiType: model.PIIDateOfBirth,   strategy: model.StrategyRangeGeneralization},
    },
    model.CategoryManufacturing: { // DC-02
        {piiType: model.PIIWorkerID,     strategy: model.StrategyDeterministicTokenization},
        {piiType: model.PIIProductCode,  strategy: model.StrategyPartialMasking},
    },
    model.CategoryHRFinance: { // DC-03
        {piiType: model.PIIKoreanName,  strategy: model.StrategyDeterministicTokenization},
        {piiType: model.PIIKoreanRRN,   strategy: model.StrategyHMACSHA256},
        {piiType: model.PIIEmployeeID,  strategy: model.StrategyDeterministicTokenization},
        {piiType: model.PIISalary,      strategy: model.StrategyEncryption},
        {piiType: model.PIIDateOfBirth, strategy: model.StrategyRangeGeneralization},
        {piiType: model.PIIKoreanMobile,strategy: model.StrategyPartialMasking},
        {piiType: model.PIIEmail,       strategy: model.StrategyDeterministicTokenization},
    },
}
```

`maskForSearch: true` on `PIIKoreanMobile` causes the engine to emit an additional `{field}_search_token` field alongside the masked display value, enabling exact-match queries on the token while showing only the masked value to users.

---

## Engine — full anonymization flow

### `Anonymize()` — two-phase pipeline

```go
// internal/anonymizer/engine.go

func (e *Engine) Anonymize(ctx context.Context, req *model.AnonymizeRequest) (*model.AnonymizeResponse, error) {

    // ── Phase 1: Detect and index ────────────────────────────────────────────
    // Run the classifier on the first record to discover which fields contain
    // which PII types. All subsequent records in the batch use the same index,
    // so classification cost is O(1) per batch rather than O(n).
    policies := categoryPolicies[req.Category]
    detections := e.buildDetectionIndex(req.Records, policies)

    // ── Resolve key material ─────────────────────────────────────────────────
    // Both HMAC key and DEK are tenant×category scoped.
    // This is the only KMS round-trip per batch; results are cached in Manager.
    hmacKey, encKey, err := e.resolveKeyMaterial(ctx, req.TenantID, req.Category)
    if err != nil {
        return nil, fmt.Errorf("anonymize: key material: %w", err)
    }

    // ── Phase 2: Transform ───────────────────────────────────────────────────
    output := make([]map[string]any, 0, len(req.Records))
    meta := model.AnonymizeMetadata{StrategiesApplied: make(map[string]int)}

    for _, record := range req.Records {
        out, fieldsProcessed, stratUsed, err := e.transformRecord(
            ctx, record, detections, hmacKey, encKey, req.AccessLevel, req.TenantID)
        if err != nil {
            return nil, fmt.Errorf("anonymize: transforming record: %w", err)
        }
        output = append(output, out)
        meta.FieldsAnonymized += fieldsProcessed
        for s, n := range stratUsed {
            meta.StrategiesApplied[s] += n
        }
    }
    meta.RecordCount = len(output)

    // ── Audit log ────────────────────────────────────────────────────────────
    auditID, _ := e.auditor.Log(ctx, model.AuditEvent{
        TenantID:     req.TenantID,
        EventType:    model.AuditEventAnonymize,
        ActorID:      req.RequesterID,
        ResourceType: string(req.Category),
        Action:       "anonymize",
        Outcome:      "success",
        Metadata:     map[string]any{"record_count": meta.RecordCount, "purpose": req.Purpose},
    })

    return &model.AnonymizeResponse{
        TenantID: req.TenantID,
        Category: req.Category,
        Records:  output,
        AuditID:  auditID,
        Metadata: meta,
    }, nil
}
```

### `buildDetectionIndex()` — classify once for the batch

```go
func (e *Engine) buildDetectionIndex(records []map[string]any, policies []fieldPolicy) map[string]fieldPolicy {
    index := make(map[string]fieldPolicy)
    if len(records) == 0 {
        return index
    }

    // Classify only the first record. This assumes records in a batch are
    // structurally homogeneous (same field names, same PII types per field).
    detections := e.classifier.DetectPII(records[0])

    // Cross-reference detected PII types with the category's policy list.
    // Only fields that have a policy in categoryPolicies are anonymized;
    // non-PII fields pass through untouched.
    for _, det := range detections {
        for _, pol := range policies {
            if pol.piiType == det.PIIType {
                index[det.Field] = pol
                break
            }
        }
    }
    return index
}
```

### `transformRecord()` — apply strategy per field

```go
func (e *Engine) transformRecord(
    ctx context.Context,
    record map[string]any,
    detections map[string]fieldPolicy,
    hmacKey, encKey []byte,
    accessLevel model.AccessLevel,
    tenantID string,
) (map[string]any, int, map[string]int, error) {

    out := make(map[string]any, len(record))
    fieldsProcessed := 0
    stratUsed := make(map[string]int)

    for k, v := range record {
        pol, hasPII := detections[k]
        if !hasPII {
            out[k] = v  // non-PII field: pass through unchanged
            continue
        }

        strVal := fmt.Sprintf("%v", v)
        strategy := e.strategyMap[pol.strategy]

        // All strategies receive the same Params bundle. They take only what
        // they need: HMAC strategies ignore EncryptionKey, encryption strategy
        // ignores HMACKey, etc.
        params := strategies.Params{
            HMACKey:       hmacKey,
            EncryptionKey: encKey,
            FieldHint:     k,        // used by range_generalization switch
            TenantID:      tenantID, // scopes tokendb registry lookup
        }

        transformed, err := strategy.Apply(ctx, strVal, params)
        if err != nil {
            return nil, 0, nil, fmt.Errorf("field %q: %w", k, err)
        }
        out[k] = transformed
        fieldsProcessed++
        stratUsed[strategy.Name()]++

        // maskForSearch: emit a deterministic search token alongside the
        // masked display value so that exact-match queries still work on
        // mobile numbers without exposing the real digits.
        //
        // Example output:
        //   "mobile":              "010-****-5678"   (display)
        //   "mobile_search_token": "TOK:RjIzb..."    (lookup key)
        if pol.maskForSearch {
            tokenizer := e.strategyMap[model.StrategyDeterministicTokenization]
            if token, terr := tokenizer.Apply(ctx, strVal, params); terr == nil {
                out[k+"_search_token"] = token
            }
        }
    }

    return out, fieldsProcessed, stratUsed, nil
}
```

### `Deanonymize()` — reversal of encryption-only fields

```go
func (e *Engine) Deanonymize(ctx context.Context, req *model.DeanonymizeRequest) (*model.AnonymizeResponse, error) {
    // Only the DEK is needed for deanonymization; HMAC keys are irrelevant
    // because HMAC and masking strategies are not reversible.
    _, encKey, err := e.resolveKeyMaterial(ctx, req.TenantID, req.Category)
    if err != nil {
        return nil, fmt.Errorf("deanonymize: key material: %w", err)
    }

    output := make([]map[string]any, 0, len(req.Records))
    for _, record := range req.Records {
        out, err := e.reverseRecord(ctx, record, encKey)
        if err != nil {
            return nil, fmt.Errorf("deanonymize: %w", err)
        }
        output = append(output, out)
    }
    // ...audit log and return
}

// reverseRecord only reverses fields that carry the "ENC:" prefix.
// All other fields (TOK:, HMAC:, ****) are returned as-is.
func (e *Engine) reverseRecord(ctx context.Context, record map[string]any, encKey []byte) (map[string]any, error) {
    enc := e.strategyMap[model.StrategyEncryption]
    out := make(map[string]any, len(record))
    for k, v := range record {
        strVal := fmt.Sprintf("%v", v)
        if strings.HasPrefix(strVal, "ENC:") {
            params := strategies.Params{EncryptionKey: encKey}
            pt, err := enc.Reverse(ctx, strVal, params)
            if err != nil {
                return nil, fmt.Errorf("reversing field %q: %w", k, err)
            }
            out[k] = pt
        } else {
            out[k] = v  // HMAC:, TOK:, masked, or plain — not reversed
        }
    }
    return out, nil
}
```

---

## End-to-end trace — Customer record (DC-01)

**Input record:**
```json
{
  "name":           "홍길동",
  "rrn":            "850315-1234567",
  "mobile":         "010-1234-5678",
  "email":          "hong@example.com",
  "address_detail": "강남구 역삼동 123-45",
  "address_city":   "서울특별시 강남구 역삼동",
  "credit_card":    "1234567890123456",
  "birth_date":     "1985-03-15"
}
```

**`resolveKeyMaterial("acme-corp", "DC-01")`:**
```
masterKeyID = "tenant:acme-corp:category:DC-01"
hmacKey     = KMS.GenerateHMACKey("tenant:acme-corp:category:DC-01")
encKey      = KMS.GetOrGenerateDEK("tenant:acme-corp:category:DC-01")
```

**`buildDetectionIndex` (first record):**
```
classifier.DetectPII(record) →
  name         → PIIKoreanName    → StrategyDeterministicTokenization
  rrn          → PIIKoreanRRN     → StrategyHMACSHA256
  mobile       → PIIKoreanMobile  → StrategyPartialMasking (maskForSearch=true)
  email        → PIIEmail         → StrategyDeterministicTokenization
  address_detail → PIIAddressDetail → StrategySuppression
  address_city → PIIAddressCity   → StrategyGeneralization
  credit_card  → PIICreditCard    → StrategyPartialMasking
  birth_date   → PIIDateOfBirth   → StrategyRangeGeneralization
```

**`transformRecord`:**

| Field | Strategy | Output |
|---|---|---|
| `name` | deterministic_tokenization | `TOK:RjIzbTYxdmVBcFVNVVhi` |
| `rrn` | hmac_sha256 | `HMAC:3e9c7a2f...` (64 hex chars) |
| `mobile` | partial_masking | `010-****-5678` |
| `mobile_search_token` | deterministic_tokenization (extra) | `TOK:xK3mN9pQrZ...` |
| `email` | deterministic_tokenization | `TOK:Ab7cD3eF...` |
| `address_detail` | suppression | `[REMOVED]` |
| `address_city` | generalization (level 1) | `서울특별시 강남구` |
| `credit_card` | partial_masking | `1234-****-****-3456` |
| `birth_date` | range_generalization (birth hint) | `1980s` |

**Output record:**
```json
{
  "name":                "TOK:RjIzbTYxdmVBcFVNVVhi",
  "rrn":                 "HMAC:3e9c7a2f4b1d8e6a...",
  "mobile":              "010-****-5678",
  "mobile_search_token": "TOK:xK3mN9pQrZ...",
  "email":               "TOK:Ab7cD3eF...",
  "address_detail":      "[REMOVED]",
  "address_city":        "서울특별시 강남구",
  "credit_card":         "1234-****-****-3456",
  "birth_date":          "1980s"
}
```

**Strategy reversibility summary:**

| Field | Strategy | Reversible? | Method |
|---|---|---|---|
| `name` | deterministic_tokenization | Yes | tokendb registry lookup |
| `rrn` | hmac_sha256 | No | — |
| `mobile` | partial_masking | No | — |
| `email` | deterministic_tokenization | Yes | tokendb registry lookup |
| `address_detail` | suppression | No | — |
| `address_city` | generalization | No | — |
| `credit_card` | partial_masking | No | — |
| `birth_date` | range_generalization | No | — |
| *(salary in HR-Finance)* | encryption | Yes | AES-256-GCM with DEK |

---

## Faker rewrite (Vault Phase-1 → Navigator handoff)

After `Anonymize()` produces `TOK:` tokens, the Navigator's `TokenRewriter` replaces them with semantically plausible fake values before embedding. This prevents the BGE-M3 embedding model from receiving opaque token strings that would degrade vector search quality.

```
Vault Phase-1 output:   "name": "TOK:RjIzbTYxdmVBcFVNVVhi"
TokenRewriter output:   "name": "James Anderson_RjIzbT"
                                              ↑ hex suffix = first 6 chars of token
                                                (preserved for Phase-2 reversal)
```

The hex suffix allows Vault Phase-2 to re-identify the original `TOK:` value and reverse it.

---

## Related documents

- `vault/docs/multi-tenancy.md` — tenant isolation, RBAC, cross-tenant verifier
- `docs/11_module_vault_srs_v3.md` — full Vault SRS specification (§3.3 PII Strategy Table)
- `docs/32_injection_defense_architecture.md` — injection defense overview (D-08, D-09)
