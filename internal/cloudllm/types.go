// Package cloudllm implements the Vault Cloud LLM Connector extension.
// It anonymizes LLM message payloads before sending to cloud providers,
// and de-anonymizes the response before returning to the caller.
// See docs/21_extension_vault_cloud_llm_v1.md.
package cloudllm

// LLMMessage is a single chat message (role + content).
type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LLMOptions holds optional generation parameters forwarded to the provider.
type LLMOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
}

// LLMCallRequest is the public API request body for POST /v1/vault/llm/complete.
type LLMCallRequest struct {
	Messages     []LLMMessage `json:"messages"`
	DataCategory string       `json:"data_category"`
	Provider     string       `json:"provider,omitempty"`
	Model        string       `json:"model,omitempty"`
	UserID       string       `json:"user_id"`
	TenantID     string       `json:"tenant_id"`
	Options      *LLMOptions  `json:"options,omitempty"`
}

// AnonymizationSummary reports what the connector anonymized and later restored.
type AnonymizationSummary struct {
	FieldsAnonymized   int `json:"fields_anonymized"`
	TokensInResponse   int `json:"tokens_in_response"`
	TokensDeanonymized int `json:"tokens_deanonymized"`
}

// LLMCallResponse is the public API response body.
type LLMCallResponse struct {
	Message       LLMMessage           `json:"message"`
	Anonymization AnonymizationSummary `json:"anonymization"`
	Provider      string               `json:"provider"`
	Model         string               `json:"model"`
	TraceID       string               `json:"trace_id,omitempty"`
}

// providerRequest is the internal normalized request passed to a CloudLLMProvider.
type providerRequest struct {
	Messages []LLMMessage
	Model    string
	Options  *LLMOptions
}

// providerResponse is the raw response from a CloudLLMProvider.
type providerResponse struct {
	Message LLMMessage
	Model   string
}
