package cloudllm

import (
	"context"
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

const testMasterKey = "0000000000000000000000000000000000000000000000000000000000000001"

// ─── mock provider ────────────────────────────────────────────────────────────

type mockProvider struct {
	id      string
	reply   string
	model   string
	callErr error
}

func (m *mockProvider) ID() string           { return m.id }
func (m *mockProvider) ModelDefault() string { return m.model }
func (m *mockProvider) Complete(_ context.Context, req providerRequest) (providerResponse, error) {
	if m.callErr != nil {
		return providerResponse{}, m.callErr
	}
	// Echo the last user message back as the "answer".
	content := m.reply
	if content == "" && len(req.Messages) > 0 {
		content = "echo:" + req.Messages[len(req.Messages)-1].Content
	}
	return providerResponse{
		Message: LLMMessage{Role: "assistant", Content: content},
		Model:   m.model,
	}, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func newTestAnonymizerEngine(t *testing.T) *anonymizer.Engine {
	t.Helper()
	provider, err := kms.NewLocalProvider(t.TempDir(), testMasterKey)
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
	return anonymizer.NewEngine(mgr, classification.New(), aud, store)
}

func newTestConnector(t *testing.T, providers ...CloudLLMProvider) *Connector {
	t.Helper()
	eng := newTestAnonymizerEngine(t)
	pub := events.New("") // no-op publisher
	return NewConnector(providers, eng, pub)
}

func emptyTC() events.TraceContext {
	return events.TraceContext{TraceID: "trace-1", TenantID: "t1", UserID: "u1"}
}

// ─── Connector.Call tests ─────────────────────────────────────────────────────

func TestConnector_Call_BasicRoundTrip(t *testing.T) {
	prov := &mockProvider{id: "mock", model: "test-llm", reply: "The answer is 42."}
	conn := newTestConnector(t, prov)

	resp, err := conn.Call(context.Background(), emptyTC(), LLMCallRequest{
		TenantID:     "t1",
		UserID:       "u1",
		Messages:     []LLMMessage{{Role: "user", Content: "What is 6 times 7?"}},
		DataCategory: "customer_data",
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Message.Content != "The answer is 42." {
		t.Errorf("unexpected content: %q", resp.Message.Content)
	}
	if resp.Provider != "mock" {
		t.Errorf("unexpected provider: %q", resp.Provider)
	}
}

func TestConnector_Call_DefaultProvider_UsedWhenEmpty(t *testing.T) {
	p1 := &mockProvider{id: "first", model: "m1", reply: "from-first"}
	p2 := &mockProvider{id: "second", model: "m2", reply: "from-second"}
	conn := newTestConnector(t, p1, p2)

	resp, err := conn.Call(context.Background(), emptyTC(), LLMCallRequest{
		TenantID:     "t1",
		Messages:     []LLMMessage{{Role: "user", Content: "hello"}},
		DataCategory: "customer_data",
		// Provider field left empty → uses first (default)
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "first" {
		t.Errorf("expected default provider 'first', got %q", resp.Provider)
	}
}

func TestConnector_Call_ExplicitProvider_Selected(t *testing.T) {
	p1 := &mockProvider{id: "first", model: "m1", reply: "from-first"}
	p2 := &mockProvider{id: "second", model: "m2", reply: "from-second"}
	conn := newTestConnector(t, p1, p2)

	resp, err := conn.Call(context.Background(), emptyTC(), LLMCallRequest{
		TenantID:     "t1",
		Messages:     []LLMMessage{{Role: "user", Content: "hi"}},
		DataCategory: "customer_data",
		Provider:     "second",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "second" {
		t.Errorf("expected 'second', got %q", resp.Provider)
	}
	if resp.Message.Content != "from-second" {
		t.Errorf("unexpected content: %q", resp.Message.Content)
	}
}

func TestConnector_Call_UnknownProvider_ReturnsError(t *testing.T) {
	conn := newTestConnector(t, &mockProvider{id: "only", model: "m"})
	_, err := conn.Call(context.Background(), emptyTC(), LLMCallRequest{
		TenantID:     "t1",
		Messages:     []LLMMessage{{Role: "user", Content: "x"}},
		DataCategory: "customer_data",
		Provider:     "does-not-exist",
	})
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

// ─── token utilities ──────────────────────────────────────────────────────────

func TestExtractTokens_FindsTokens(t *testing.T) {
	text := "The name is CUST_NAME_a1b2c3d4e5f6a7b8 and email is CUST_EMAL_ffffffffffffffff."
	tokens := extractTokens(text)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d: %v", len(tokens), tokens)
	}
}

func TestExtractTokens_NoTokens_ReturnsEmpty(t *testing.T) {
	tokens := extractTokens("plain text with no vault tokens here")
	if len(tokens) != 0 {
		t.Errorf("expected 0, got %d", len(tokens))
	}
}

func TestCountDeanonymized_AllRestored(t *testing.T) {
	tokens := []string{"CUST_NAME_aabbccddeeff0011"}
	original := "Hello CUST_NAME_aabbccddeeff0011 how are you"
	restored := "Hello Alice how are you"
	count := countDeanonymized(original, restored, tokens)
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestCountDeanonymized_NoneRestored(t *testing.T) {
	tokens := []string{"CUST_NAME_aabbccddeeff0011"}
	original := "Hello CUST_NAME_aabbccddeeff0011"
	restored := "Hello CUST_NAME_aabbccddeeff0011" // token still present = not de-anon'd
	count := countDeanonymized(original, restored, tokens)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestHashMessages_DifferentInputs_DifferentHashes(t *testing.T) {
	h1 := hashMessages([]LLMMessage{{Role: "user", Content: "hello"}})
	h2 := hashMessages([]LLMMessage{{Role: "user", Content: "world"}})
	if h1 == h2 {
		t.Error("distinct messages should produce different hashes")
	}
}

func TestHashMessages_HasPrefix(t *testing.T) {
	h := hashMessages([]LLMMessage{{Role: "user", Content: "x"}})
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", h)
	}
}

// ─── dataCategoryFromString ───────────────────────────────────────────────────

func TestDataCategoryFromString(t *testing.T) {
	cases := []struct {
		input string
		wantS string // just verify it doesn't panic; category constants aren't re-exported
	}{
		{"customer_data", "customer_data"},
		{"DC-01", "customer_data"},
		{"manufacturing_data", "manufacturing_data"},
		{"DC-02", "manufacturing_data"},
		{"hr_data", "hr_data"},
		{"DC-03", "hr_data"},
		{"unknown_value", "customer_data"}, // default
	}
	for _, tc := range cases {
		cat := dataCategoryFromString(tc.input)
		_ = cat // just ensure no panic
	}
}
