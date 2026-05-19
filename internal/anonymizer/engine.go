package anonymizer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zafrem/bastion-vault/internal/anonymizer/strategies"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// fieldPolicy describes which strategy to apply to a PII field
type fieldPolicy struct {
	piiType    model.PIIType
	strategy   model.AnonymizationStrategy
	maskForSearch bool // when true, a separate search token is also produced
}

// categoryPolicies maps each data category to its field-level anonymization rules.
// This implements the SRS §3.3 PII Strategy Table.
var categoryPolicies = map[model.DataCategory][]fieldPolicy{
	model.CategoryCustomer: {
		{piiType: model.PIIKoreanName, strategy: model.StrategyDeterministicTokenization},
		{piiType: model.PIIKoreanRRN, strategy: model.StrategyHMACSHA256},
		{piiType: model.PIIKoreanMobile, strategy: model.StrategyPartialMasking, maskForSearch: true},
		{piiType: model.PIIEmail, strategy: model.StrategyDeterministicTokenization},
		{piiType: model.PIIAddressDetail, strategy: model.StrategySuppression},
		{piiType: model.PIIAddressCity, strategy: model.StrategyGeneralization},
		{piiType: model.PIICreditCard, strategy: model.StrategyPartialMasking},
		{piiType: model.PIIDateOfBirth, strategy: model.StrategyRangeGeneralization},
	},
	model.CategoryManufacturing: {
		{piiType: model.PIIWorkerID, strategy: model.StrategyDeterministicTokenization},
		{piiType: model.PIIProductCode, strategy: model.StrategyPartialMasking},
	},
	model.CategoryHRFinance: {
		{piiType: model.PIIKoreanName, strategy: model.StrategyDeterministicTokenization},
		{piiType: model.PIIKoreanRRN, strategy: model.StrategyHMACSHA256},
		{piiType: model.PIIEmployeeID, strategy: model.StrategyDeterministicTokenization},
		{piiType: model.PIISalary, strategy: model.StrategyEncryption},
		{piiType: model.PIIDateOfBirth, strategy: model.StrategyRangeGeneralization},
		{piiType: model.PIIKoreanMobile, strategy: model.StrategyPartialMasking},
		{piiType: model.PIIEmail, strategy: model.StrategyDeterministicTokenization},
	},
}

// Engine applies Phase-1 (strategy selection) and Phase-2 (transformation) anonymization.
type Engine struct {
	kmsManager *kms.Manager
	classifier *classification.Classifier
	auditor    *audit.Logger
	strategyMap map[model.AnonymizationStrategy]strategies.Strategy
}

// NewEngine wires up the anonymization engine with all required dependencies.
// store may be nil; when provided, deterministic tokenization persists reverse-lookup
// mappings so that Deanonymize can recover tokenized values.
func NewEngine(mgr *kms.Manager, cls *classification.Classifier, aud *audit.Logger, store tokendb.Store) *Engine {
	tok := strategies.NewTokenization()
	if store != nil {
		tok = tok.WithStore(store)
	}
	return &Engine{
		kmsManager: mgr,
		classifier: cls,
		auditor:    aud,
		strategyMap: map[model.AnonymizationStrategy]strategies.Strategy{
			model.StrategyDeterministicTokenization: tok,
			model.StrategyHMACSHA256:                strategies.NewHMAC(),
			model.StrategyPartialMasking:            strategies.NewMasking(),
			model.StrategyGeneralization:            strategies.NewGeneralization(),
			model.StrategyRangeGeneralization:       strategies.NewRangeGeneralization(),
			model.StrategySuppression:               strategies.NewSuppression(),
			model.StrategyEncryption:                strategies.NewEncryption(),
			model.StrategyFPEEmail:                  tok, // FPE approximated via tokenization
		},
	}
}

// Anonymize runs the full two-phase anonymization pipeline on a request.
// Phase 1: detect PII fields and select per-field strategy.
// Phase 2: apply strategies using KMS-derived key material.
func (e *Engine) Anonymize(ctx context.Context, req *model.AnonymizeRequest) (*model.AnonymizeResponse, error) {
	policies := categoryPolicies[req.Category]
	detections := e.buildDetectionIndex(req.Records, policies)

	hmacKey, encKey, err := e.resolveKeyMaterial(ctx, req.TenantID, req.Category)
	if err != nil {
		return nil, fmt.Errorf("anonymize: key material: %w", err)
	}

	output := make([]map[string]any, 0, len(req.Records))
	meta := model.AnonymizeMetadata{
		StrategiesApplied: make(map[string]int),
		ProcessedAt:       time.Now().UTC(),
	}

	for _, record := range req.Records {
		out, fieldsProcessed, stratUsed, err := e.transformRecord(ctx, record, detections, hmacKey, encKey, req.AccessLevel, req.TenantID)
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

	auditID, _ := e.auditor.Log(ctx, model.AuditEvent{
		TenantID:     req.TenantID,
		EventType:    model.AuditEventAnonymize,
		ActorID:      req.RequesterID,
		ResourceType: string(req.Category),
		Action:       "anonymize",
		Outcome:      "success",
		Metadata: map[string]any{
			"record_count": meta.RecordCount,
			"purpose":      req.Purpose,
		},
	})

	return &model.AnonymizeResponse{
		TenantID: req.TenantID,
		Category: req.Category,
		Records:  output,
		AuditID:  auditID,
		Metadata: meta,
	}, nil
}

// Deanonymize reverses reversible fields for authorised callers.
func (e *Engine) Deanonymize(ctx context.Context, req *model.DeanonymizeRequest) (*model.AnonymizeResponse, error) {
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

	auditID, _ := e.auditor.Log(ctx, model.AuditEvent{
		TenantID:     req.TenantID,
		EventType:    model.AuditEventDeanonymize,
		ActorID:      req.RequesterID,
		ResourceType: string(req.Category),
		Action:       "deanonymize",
		Outcome:      "success",
		Metadata: map[string]any{
			"justification": req.Justification,
		},
	})

	return &model.AnonymizeResponse{
		TenantID: req.TenantID,
		Category: req.Category,
		Records:  output,
		AuditID:  auditID,
		Metadata: model.AnonymizeMetadata{
			RecordCount: len(output),
			ProcessedAt: time.Now().UTC(),
		},
	}, nil
}

// buildDetectionIndex maps field names to their PII type for faster lookup during transform
func (e *Engine) buildDetectionIndex(records []map[string]any, policies []fieldPolicy) map[string]fieldPolicy {
	index := make(map[string]fieldPolicy)
	if len(records) == 0 {
		return index
	}
	// Run classifier on the first record to discover field→pii mappings
	detections := e.classifier.DetectPII(records[0])
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

func (e *Engine) resolveKeyMaterial(ctx context.Context, tenantID string, cat model.DataCategory) (hmacKey, encKey []byte, err error) {
	masterKeyID := fmt.Sprintf("tenant:%s:category:%s", tenantID, string(cat))

	hmacKey, err = e.kmsManager.GetHMACKey(ctx, masterKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving HMAC key: %w", err)
	}

	dk, err := e.kmsManager.GetOrGenerateDEK(ctx, masterKeyID, masterKeyID+":dek")
	if err != nil {
		return nil, nil, fmt.Errorf("resolving DEK: %w", err)
	}
	encKey = dk.Plaintext

	return hmacKey, encKey, nil
}

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
			out[k] = v
			continue
		}

		strVal := fmt.Sprintf("%v", v)
		strategy, ok := e.strategyMap[pol.strategy]
		if !ok {
			out[k] = v
			continue
		}

		params := strategies.Params{
			HMACKey:       hmacKey,
			EncryptionKey: encKey,
			FieldHint:     k,
			TenantID:      tenantID,
		}

		transformed, err := strategy.Apply(ctx, strVal, params)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("field %q: %w", k, err)
		}
		out[k] = transformed
		fieldsProcessed++
		stratUsed[strategy.Name()]++

		// For mobile: also emit a search token alongside the display-masked value
		if pol.maskForSearch {
			tokenizer := e.strategyMap[model.StrategyDeterministicTokenization]
			token, terr := tokenizer.Apply(ctx, strVal, params)
			if terr == nil {
				out[k+"_search_token"] = token
			}
		}
	}

	return out, fieldsProcessed, stratUsed, nil
}

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
			out[k] = v
		}
	}
	return out, nil
}
