package cloudllm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/events"
	"github.com/zafrem/bastion-vault/internal/model"
)

// Connector anonymizes LLM message payloads, calls the cloud provider,
// then de-anonymizes the response before returning to the caller.
// The audit event is always emitted; the connector refuses to process
// if the publisher has no connection (NFR-CLLM-003 is enforced in the handler).
type Connector struct {
	providers map[string]CloudLLMProvider
	defaultID string
	engine    *anonymizer.Engine
	pub       *events.Publisher
	tokenRE   *regexp.Regexp
}

// NewConnector builds a Connector from the provided providers.
// The first provider in the slice is the default. An optional tokenPattern
// overrides DefaultTokenPattern used to detect Vault tokens in LLM responses;
// an empty or invalid pattern falls back to the default.
func NewConnector(
	providers []CloudLLMProvider,
	eng *anonymizer.Engine,
	pub *events.Publisher,
	tokenPattern ...string,
) *Connector {
	byID := make(map[string]CloudLLMProvider, len(providers))
	defaultID := ""
	for _, p := range providers {
		byID[p.ID()] = p
		if defaultID == "" {
			defaultID = p.ID()
		}
	}
	re := tokenPattern
	tokenRE := tokenPatternDefault
	if len(re) > 0 && re[0] != "" {
		if compiled, err := regexp.Compile(re[0]); err == nil {
			tokenRE = compiled
		}
	}
	return &Connector{
		providers: byID,
		defaultID: defaultID,
		engine:    eng,
		pub:       pub,
		tokenRE:   tokenRE,
	}
}

// Call executes the full anonymize → LLM → deanonymize pipeline.
func (c *Connector) Call(ctx context.Context, tc events.TraceContext, req LLMCallRequest) (LLMCallResponse, error) {
	// 1. Select provider
	providerID := req.Provider
	if providerID == "" {
		providerID = c.defaultID
	}
	prov, ok := c.providers[providerID]
	if !ok {
		return LLMCallResponse{}, fmt.Errorf("unknown provider %q", providerID)
	}

	// 2. Anonymize messages
	category := dataCategoryFromString(req.DataCategory)
	anonMessages, fieldsAnonymized, err := c.anonymizeMessages(ctx, req.Messages, category, req.TenantID, req.UserID)
	if err != nil {
		return LLMCallResponse{}, fmt.Errorf("anonymize: %w", err)
	}

	// 3. Hash anonymized payload for audit (never stores raw PII)
	anonHash := hashMessages(anonMessages)

	// 4. Call cloud LLM with anonymized messages
	model := req.Model
	if model == "" {
		model = prov.ModelDefault()
	}
	provResp, err := prov.Complete(ctx, providerRequest{
		Messages: anonMessages,
		Model:    model,
		Options:  req.Options,
	})
	if err != nil {
		return LLMCallResponse{}, fmt.Errorf("provider %s: %w", providerID, err)
	}

	// 5. De-anonymize tokens in the response
	deanonContent, tokensFound, tokensDeanon := c.deanonymizeText(ctx, provResp.Message.Content, category, req.TenantID, req.UserID)

	// 6. Emit mandatory audit event (fire-and-forget)
	c.pub.Publish(events.EventCloudLLMCalled(tc, providerID, model, req.DataCategory,
		fieldsAnonymized, tokensFound, tokensDeanon, anonHash))

	return LLMCallResponse{
		Message:  LLMMessage{Role: provResp.Message.Role, Content: deanonContent},
		Provider: providerID,
		Model:    provResp.Model,
		Anonymization: AnonymizationSummary{
			FieldsAnonymized:   fieldsAnonymized,
			TokensInResponse:   tokensFound,
			TokensDeanonymized: tokensDeanon,
		},
		TraceID: tc.TraceID,
	}, nil
}

// ─── internal helpers ─────────────────────────────────────────────────────────

// anonymizeMessages passes each message's content as a record to the Engine.
func (c *Connector) anonymizeMessages(
	ctx context.Context,
	messages []LLMMessage,
	category model.DataCategory,
	tenantID, userID string,
) ([]LLMMessage, int, error) {
	records := make([]map[string]any, len(messages))
	for i, m := range messages {
		records[i] = map[string]any{"content": m.Content}
	}

	resp, err := c.engine.Anonymize(ctx, &model.AnonymizeRequest{
		TenantID:    tenantID,
		Category:    category,
		Records:     records,
		Purpose:     "cloud_llm_call",
		RequesterID: userID,
		AccessLevel: model.AccessFull,
	})
	if err != nil {
		return nil, 0, err
	}

	out := make([]LLMMessage, len(messages))
	for i, m := range messages {
		content := m.Content
		if i < len(resp.Records) {
			if v, ok := resp.Records[i]["content"]; ok {
				content = fmt.Sprintf("%v", v)
			}
		}
		out[i] = LLMMessage{Role: m.Role, Content: content}
	}
	return out, resp.Metadata.FieldsAnonymized, nil
}

// deanonymizeText scans text for known token patterns and reverses them.
// It uses the Engine's Deanonymize on the response content.
func (c *Connector) deanonymizeText(
	ctx context.Context,
	text string,
	category model.DataCategory,
	tenantID, userID string,
) (string, int, int) {
	tokens := c.tokenRE.FindAllString(text, -1)
	if len(tokens) == 0 {
		return text, 0, 0
	}

	record := map[string]any{"content": text}
	resp, err := c.engine.Deanonymize(ctx, &model.DeanonymizeRequest{
		TenantID:      tenantID,
		Category:      category,
		Records:       []map[string]any{record},
		RequesterID:   userID,
		Justification: "cloud_llm_response_deanon",
	})
	if err != nil || len(resp.Records) == 0 {
		return text, len(tokens), 0
	}
	restored := fmt.Sprintf("%v", resp.Records[0]["content"])
	deanonCount := countDeanonymized(text, restored, tokens)
	return restored, len(tokens), deanonCount
}

// ─── token utilities ──────────────────────────────────────────────────────────

// DefaultTokenPattern matches Vault deterministic tokens of the form
// PREFIX_TYPE_hex16. Override via cloud_llm.token_pattern in vault.yaml.
const DefaultTokenPattern = `[A-Z]{2,}_[A-Z]{2,}_[a-z0-9]{16}`

// tokenPatternDefault is the compiled DefaultTokenPattern used when a Connector
// is built without an override.
var tokenPatternDefault = regexp.MustCompile(DefaultTokenPattern)

func extractTokens(text string) []string {
	return tokenPatternDefault.FindAllString(text, -1)
}

func countDeanonymized(original, restored string, tokens []string) int {
	count := 0
	for _, tok := range tokens {
		if strings.Contains(original, tok) && !strings.Contains(restored, tok) {
			count++
		}
	}
	return count
}

func hashMessages(msgs []LLMMessage) string {
	data, _ := json.Marshal(msgs)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func dataCategoryFromString(s string) model.DataCategory {
	switch s {
	case "customer_data", "DC-01":
		return model.CategoryCustomer
	case "manufacturing_data", "DC-02":
		return model.CategoryManufacturing
	case "hr_data", "hr_finance_data", "DC-03":
		return model.CategoryHRFinance
	default:
		return model.CategoryCustomer
	}
}
