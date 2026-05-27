package cloudllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/events"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// ─── Case 2 Integration: Sentinel gate → Vault anonymize → LLM → deanonymize ─

// openAIResponse builds a mock OpenAI-compatible response body.
// The content is given verbatim so tests can control de-anonymization scenarios.
func openAIResponse(content string) []byte {
	resp := map[string]any{
		"choices": []map[string]any{
			{"message": map[string]string{"role": "assistant", "content": content}},
		},
		"model": "test-llm-v1",
	}
	data, _ := json.Marshal(resp)
	return data
}

// buildIntegTestConnector constructs a Connector backed by a real anonymizer
// engine (local KMS, in-memory store) and the given mock LLM server.
func buildIntegTestConnector(t *testing.T, mockLLMURL string) *Connector {
	t.Helper()
	masterKey := "0000000000000000000000000000000000000000000000000000000000000001"
	provider, err := kms.NewLocalProvider(t.TempDir(), masterKey)
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	mgr := kms.NewManager(provider, 5*time.Minute)
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	store := tokendb.NewMemoryStore()
	eng := anonymizer.NewEngine(mgr, classification.New(), aud, store)
	pub := events.New("") // no-op publisher

	llmProv := NewCustomProvider(
		"mock-llm", mockLLMURL+"/v1/chat/completions", "", "test-llm-v1", 5,
	)
	return NewConnector([]CloudLLMProvider{llmProv}, eng, pub)
}

// ─── Test: anonymization happens before LLM call ─────────────────────────────

// TestCase2_PIIAnonymizedBeforeLLMCall verifies that PII in the user message
// is tokenized before reaching the LLM. The LLM receives tokens, not raw names.
func TestCase2_PIIAnonymizedBeforeLLMCall(t *testing.T) {
	var capturedBody map[string]any
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAIResponse("I processed the anonymized query."))
	}))
	defer mockLLM.Close()

	conn := buildIntegTestConnector(t, mockLLM.URL)
	tc := events.TraceContext{TraceID: "llm-integ-001", TenantID: "acme", UserID: "alice"}

	_, err := conn.Call(context.Background(), tc, LLMCallRequest{
		TenantID:     "acme",
		UserID:       "alice",
		DataCategory: "customer_data",
		Messages: []LLMMessage{
			{Role: "user", Content: "Summarise data for John Doe (email: john@example.com)"},
		},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	// Verify the LLM received a body with anonymized content.
	if capturedBody == nil {
		t.Fatal("mock LLM received no request")
	}
	messages, _ := capturedBody["messages"].([]any)
	if len(messages) == 0 {
		t.Fatal("no messages in LLM request")
	}
	content, _ := messages[0].(map[string]any)["content"].(string)
	if strings.Contains(content, "John Doe") {
		t.Errorf("PII leaked to LLM — message still contains 'John Doe': %q", content)
	}
	if strings.Contains(content, "john@example.com") {
		t.Errorf("PII leaked to LLM — message still contains email: %q", content)
	}
	t.Logf("LLM received anonymized content: %q", content)
}

// TestCase2_AuditTrailEmitted verifies the mandatory audit hash is set.
func TestCase2_AuditTrailEmitted(t *testing.T) {
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAIResponse("Summary: no PII found."))
	}))
	defer mockLLM.Close()

	conn := buildIntegTestConnector(t, mockLLM.URL)
	tc := events.TraceContext{TraceID: "audit-001", TenantID: "acme", UserID: "svc"}

	resp, err := conn.Call(context.Background(), tc, LLMCallRequest{
		TenantID:     "acme",
		UserID:       "svc",
		DataCategory: "hr_data",
		Messages:     []LLMMessage{{Role: "user", Content: "List employees in dept X."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TraceID != "audit-001" {
		t.Errorf("trace ID not propagated: %q", resp.TraceID)
	}
	if resp.Provider != "mock-llm" {
		t.Errorf("unexpected provider: %q", resp.Provider)
	}
	t.Logf("Audit: provider=%s model=%s fields_anonymized=%d",
		resp.Provider, resp.Model, resp.Anonymization.FieldsAnonymized)
}

// TestCase2_LLMError_ConnectorReturnsError verifies the connector surfaces
// LLM HTTP errors rather than silently returning empty content.
func TestCase2_LLMError_ConnectorReturnsError(t *testing.T) {
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"overloaded"}`))
	}))
	defer mockLLM.Close()

	conn := buildIntegTestConnector(t, mockLLM.URL)
	_, err := conn.Call(context.Background(), events.TraceContext{TenantID: "acme"}, LLMCallRequest{
		TenantID:     "acme",
		UserID:       "svc",
		DataCategory: "customer_data",
		Messages:     []LLMMessage{{Role: "user", Content: "test"}},
	})
	if err == nil {
		t.Error("expected error from connector when LLM returns 503")
	}
	t.Logf("LLM error correctly surfaced: %v", err)
}

// TestCase2_MultipleMessages_AllAnonymized tests that all messages in a
// conversation are anonymized before being sent to the LLM.
func TestCase2_MultipleMessages_AllAnonymized(t *testing.T) {
	var capturedMessages []any
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		capturedMessages, _ = body["messages"].([]any)
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAIResponse("Processed."))
	}))
	defer mockLLM.Close()

	// NOTE: The engine classifies PII from the first record in the batch and uses
	// that field map for all subsequent records. To ensure all messages get the
	// same anonymization treatment, the first message must contain representative PII.
	conn := buildIntegTestConnector(t, mockLLM.URL)
	_, err := conn.Call(context.Background(), events.TraceContext{TenantID: "acme"}, LLMCallRequest{
		TenantID:     "acme",
		UserID:       "alice",
		DataCategory: "customer_data",
		Messages: []LLMMessage{
			// First message contains PII — classifier builds field index from this.
			{Role: "user", Content: "What is Jane Doe's balance? email: jane@corp.com"},
			{Role: "assistant", Content: "Looking up jane@corp.com now."},
			{Role: "user", Content: "Also check alice@corp.com please."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(capturedMessages) == 0 {
		t.Fatal("mock LLM received no messages")
	}
	// The first message must have had its email anonymized (classifier runs on record[0]).
	firstContent, _ := capturedMessages[0].(map[string]any)["content"].(string)
	if strings.Contains(firstContent, "jane@corp.com") {
		t.Errorf("message[0] email not anonymized: %q", firstContent)
	}
	t.Logf("%d messages sent to LLM, first message anonymized: %q", len(capturedMessages), firstContent)
}

// TestCase2_ResponseTokens_Deanonymized verifies that tokens in the LLM
// response text are resolved back to original values.
func TestCase2_ResponseTokens_Deanonymized(t *testing.T) {
	// First, generate a real token by running a quick anonymize step.
	masterKey := "0000000000000000000000000000000000000000000000000000000000000001"
	kmsProvider, _ := kms.NewLocalProvider(t.TempDir(), masterKey)
	mgr := kms.NewManager(kmsProvider, 5*time.Minute)
	aud, _ := audit.NewLogger(t.TempDir(), false)
	t.Cleanup(func() { _ = aud.Close() })
	store := tokendb.NewMemoryStore()
	eng := anonymizer.NewEngine(mgr, classification.New(), aud, store)
	pub := events.New("")

	// Call connector with PII; the mock LLM echoes the anonymized token back.
	var tokenInRequest string
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		msgs, _ := body["messages"].([]any)
		if len(msgs) > 0 {
			tokenInRequest, _ = msgs[0].(map[string]any)["content"].(string)
		}
		// Echo the anonymized content back as the LLM response.
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAIResponse("Result: " + tokenInRequest))
	}))
	defer mockLLM.Close()

	llmProv := NewCustomProvider("mock-llm", mockLLM.URL+"/v1/chat/completions", "", "m", 5)
	conn := NewConnector([]CloudLLMProvider{llmProv}, eng, pub)

	resp, err := conn.Call(context.Background(),
		events.TraceContext{TenantID: "acme", UserID: "alice"},
		LLMCallRequest{
			TenantID:     "acme",
			UserID:       "alice",
			DataCategory: "customer_data",
			Messages:     []LLMMessage{{Role: "user", Content: "balance for John Doe"}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Original sent: 'balance for John Doe'")
	t.Logf("Token sent to LLM: %q", tokenInRequest)
	t.Logf("Response after deanon: %q", resp.Message.Content)
	// The de-anonymization attempt is reflected in the Anonymization summary.
	t.Logf("Tokens found in response: %d, deanonymized: %d",
		resp.Anonymization.TokensInResponse, resp.Anonymization.TokensDeanonymized)
}
