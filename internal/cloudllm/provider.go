package cloudllm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CloudLLMProvider is the abstraction over cloud LLM backends.
// All implementations send anonymized messages and return a response message.
type CloudLLMProvider interface {
	ID() string
	ModelDefault() string
	Complete(ctx context.Context, req providerRequest) (providerResponse, error)
}

// ─── API key resolution ───────────────────────────────────────────────────────

// resolveAPIKey resolves a KMS reference string to a plaintext API key.
//
//   - "env://VAR_NAME"   → os.Getenv("VAR_NAME")
//   - "plain://key"      → the literal string after the prefix (dev only)
//   - anything else      → treated as env var name for backward compat
func resolveAPIKey(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "env://"):
		name := strings.TrimPrefix(ref, "env://")
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("env var %q is not set", name)
		}
		return val, nil
	case strings.HasPrefix(ref, "plain://"):
		return strings.TrimPrefix(ref, "plain://"), nil
	default:
		val := os.Getenv(ref)
		if val == "" {
			return "", fmt.Errorf("api key reference %q not resolved (env var not set)", ref)
		}
		return val, nil
	}
}

// ─── shared HTTP helper ───────────────────────────────────────────────────────

func doPost(ctx context.Context, url, authHeader string, body []byte, timeoutS int) ([]byte, error) {
	client := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("provider HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

// ─── OpenAI provider ─────────────────────────────────────────────────────────

// OpenAIProvider implements CloudLLMProvider for OpenAI Chat Completions.
type OpenAIProvider struct {
	apiKeyRef  string
	model      string
	timeoutS   int
}

func NewOpenAIProvider(apiKeyRef, model string, timeoutS int) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if timeoutS <= 0 {
		timeoutS = 30
	}
	return &OpenAIProvider{apiKeyRef: apiKeyRef, model: model, timeoutS: timeoutS}
}

func (p *OpenAIProvider) ID() string           { return "openai" }
func (p *OpenAIProvider) ModelDefault() string { return p.model }

func (p *OpenAIProvider) Complete(ctx context.Context, req providerRequest) (providerResponse, error) {
	key, err := resolveAPIKey(p.apiKeyRef)
	if err != nil {
		return providerResponse{}, fmt.Errorf("openai: %w", err)
	}
	model := req.Model
	if model == "" {
		model = p.model
	}

	type openAIMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type openAIReq struct {
		Model       string      `json:"model"`
		Messages    []openAIMsg `json:"messages"`
		Temperature float64     `json:"temperature,omitempty"`
		MaxTokens   int         `json:"max_tokens,omitempty"`
	}
	msgs := make([]openAIMsg, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = openAIMsg{Role: m.Role, Content: m.Content}
	}
	body, _ := json.Marshal(openAIReq{
		Model:       model,
		Messages:    msgs,
		Temperature: func() float64 { if req.Options != nil { return req.Options.Temperature }; return 0 }(),
		MaxTokens:   func() int { if req.Options != nil { return req.Options.MaxTokens }; return 0 }(),
	})

	data, err := doPost(ctx, "https://api.openai.com/v1/chat/completions",
		"Bearer "+key, body, p.timeoutS)
	if err != nil {
		return providerResponse{}, fmt.Errorf("openai: %w", err)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return providerResponse{}, fmt.Errorf("openai: parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return providerResponse{}, fmt.Errorf("openai: empty choices")
	}
	return providerResponse{
		Message: LLMMessage{Role: result.Choices[0].Message.Role, Content: result.Choices[0].Message.Content},
		Model:   result.Model,
	}, nil
}

// ─── Claude (Anthropic) provider ─────────────────────────────────────────────

// ClaudeProvider implements CloudLLMProvider for the Anthropic Messages API.
type ClaudeProvider struct {
	apiKeyRef string
	model     string
	timeoutS  int
}

func NewClaudeProvider(apiKeyRef, model string, timeoutS int) *ClaudeProvider {
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	if timeoutS <= 0 {
		timeoutS = 30
	}
	return &ClaudeProvider{apiKeyRef: apiKeyRef, model: model, timeoutS: timeoutS}
}

func (p *ClaudeProvider) ID() string           { return "claude" }
func (p *ClaudeProvider) ModelDefault() string { return p.model }

func (p *ClaudeProvider) Complete(ctx context.Context, req providerRequest) (providerResponse, error) {
	key, err := resolveAPIKey(p.apiKeyRef)
	if err != nil {
		return providerResponse{}, fmt.Errorf("claude: %w", err)
	}
	model := req.Model
	if model == "" {
		model = p.model
	}

	type claudeMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type claudeReq struct {
		Model     string      `json:"model"`
		MaxTokens int         `json:"max_tokens"`
		Messages  []claudeMsg `json:"messages"`
	}
	maxTokens := 1024
	if req.Options != nil && req.Options.MaxTokens > 0 {
		maxTokens = req.Options.MaxTokens
	}
	msgs := make([]claudeMsg, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role != "system" { // Claude uses system param, not system message
			msgs = append(msgs, claudeMsg{Role: m.Role, Content: m.Content})
		}
	}
	body, _ := json.Marshal(claudeReq{Model: model, MaxTokens: maxTokens, Messages: msgs})

	client := &http.Client{Timeout: time.Duration(p.timeoutS) * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return providerResponse{}, fmt.Errorf("claude: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", key)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := client.Do(httpReq)
	if err != nil {
		return providerResponse{}, fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return providerResponse{}, fmt.Errorf("claude: HTTP %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return providerResponse{}, fmt.Errorf("claude: parse response: %w", err)
	}
	text := ""
	for _, c := range result.Content {
		if c.Type == "text" {
			text = c.Text
			break
		}
	}
	return providerResponse{
		Message: LLMMessage{Role: "assistant", Content: text},
		Model:   result.Model,
	}, nil
}

// ─── Custom HTTP provider ─────────────────────────────────────────────────────

// CustomProvider calls any OpenAI-compatible HTTP endpoint.
type CustomProvider struct {
	id        string
	endpoint  string
	apiKeyRef string
	model     string
	timeoutS  int
}

func NewCustomProvider(id, endpoint, apiKeyRef, model string, timeoutS int) *CustomProvider {
	if timeoutS <= 0 {
		timeoutS = 30
	}
	return &CustomProvider{id: id, endpoint: endpoint, apiKeyRef: apiKeyRef, model: model, timeoutS: timeoutS}
}

func (p *CustomProvider) ID() string           { return p.id }
func (p *CustomProvider) ModelDefault() string { return p.model }

func (p *CustomProvider) Complete(ctx context.Context, req providerRequest) (providerResponse, error) {
	authHeader := ""
	if p.apiKeyRef != "" {
		key, err := resolveAPIKey(p.apiKeyRef)
		if err == nil && key != "" {
			authHeader = "Bearer " + key
		}
	}
	model := req.Model
	if model == "" {
		model = p.model
	}

	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type openAICompatReq struct {
		Model    string `json:"model"`
		Messages []msg  `json:"messages"`
	}
	msgs := make([]msg, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = msg{Role: m.Role, Content: m.Content}
	}
	body, _ := json.Marshal(openAICompatReq{Model: model, Messages: msgs})
	data, err := doPost(ctx, p.endpoint, authHeader, body, p.timeoutS)
	if err != nil {
		return providerResponse{}, fmt.Errorf("custom(%s): %w", p.id, err)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return providerResponse{}, fmt.Errorf("custom(%s): parse response: %w", p.id, err)
	}
	if len(result.Choices) == 0 {
		return providerResponse{}, fmt.Errorf("custom(%s): empty choices", p.id)
	}
	return providerResponse{
		Message: LLMMessage{Role: result.Choices[0].Message.Role, Content: result.Choices[0].Message.Content},
		Model:   result.Model,
	}, nil
}
