package cloudllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// ─── resolveAPIKey ────────────────────────────────────────────────────────────

func TestResolveAPIKey_EnvScheme(t *testing.T) {
	t.Setenv("TEST_LLM_KEY", "sk-test-abc")
	key, err := resolveAPIKey("env://TEST_LLM_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-test-abc" {
		t.Errorf("got %q, want %q", key, "sk-test-abc")
	}
}

func TestResolveAPIKey_EnvScheme_Missing(t *testing.T) {
	os.Unsetenv("DEFINITELY_NOT_SET_XYZ")
	_, err := resolveAPIKey("env://DEFINITELY_NOT_SET_XYZ")
	if err == nil {
		t.Error("expected error for missing env var")
	}
}

func TestResolveAPIKey_PlainScheme(t *testing.T) {
	key, err := resolveAPIKey("plain://my-literal-key")
	if err != nil {
		t.Fatal(err)
	}
	if key != "my-literal-key" {
		t.Errorf("got %q", key)
	}
}

func TestResolveAPIKey_BareEnvVar(t *testing.T) {
	t.Setenv("BARE_KEY_VAR", "bare-value")
	key, err := resolveAPIKey("BARE_KEY_VAR")
	if err != nil {
		t.Fatal(err)
	}
	if key != "bare-value" {
		t.Errorf("got %q", key)
	}
}

func TestResolveAPIKey_BareEnvVar_Missing(t *testing.T) {
	os.Unsetenv("BARE_NOT_SET_ZZZ")
	_, err := resolveAPIKey("BARE_NOT_SET_ZZZ")
	if err == nil {
		t.Error("expected error for unset bare env var")
	}
}

// ─── CustomProvider via httptest ──────────────────────────────────────────────

// openAICompatResponse returns a minimal OpenAI-compatible chat completion response.
func openAICompatResponse(content, model string) []byte {
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type choice struct {
		Message msg `json:"message"`
	}
	resp := struct {
		Choices []choice `json:"choices"`
		Model   string   `json:"model"`
	}{
		Choices: []choice{{Message: msg{Role: "assistant", Content: content}}},
		Model:   model,
	}
	data, _ := json.Marshal(resp)
	return data
}

func TestCustomProvider_Complete_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAICompatResponse("hello from local model", "test-model-v1"))
	}))
	defer srv.Close()

	p := NewCustomProvider("local", srv.URL, "", "test-model-v1", 5)
	resp, err := p.Complete(context.Background(), providerRequest{
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
		Model:    "test-model-v1",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Message.Content != "hello from local model" {
		t.Errorf("unexpected content: %q", resp.Message.Content)
	}
	if resp.Model != "test-model-v1" {
		t.Errorf("unexpected model: %q", resp.Model)
	}
}

func TestCustomProvider_Complete_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	p := NewCustomProvider("bad", srv.URL, "", "m", 5)
	_, err := p.Complete(context.Background(), providerRequest{
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestCustomProvider_Complete_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[],"model":"x"}`))
	}))
	defer srv.Close()

	p := NewCustomProvider("empty", srv.URL, "", "x", 5)
	_, err := p.Complete(context.Background(), providerRequest{
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Error("expected error for empty choices")
	}
}

func TestCustomProvider_ID(t *testing.T) {
	p := NewCustomProvider("myid", "http://localhost", "", "m", 5)
	if p.ID() != "myid" {
		t.Errorf("got %q", p.ID())
	}
}

func TestCustomProvider_ModelDefault(t *testing.T) {
	p := NewCustomProvider("x", "http://localhost", "", "llama3", 5)
	if p.ModelDefault() != "llama3" {
		t.Errorf("got %q", p.ModelDefault())
	}
}

// ─── OpenAIProvider construction ──────────────────────────────────────────────

func TestNewOpenAIProvider_Defaults(t *testing.T) {
	p := NewOpenAIProvider("plain://key", "", 0)
	if p.ModelDefault() != "gpt-4o" {
		t.Errorf("default model: got %q", p.ModelDefault())
	}
	if p.timeoutS != 30 {
		t.Errorf("default timeout: got %d", p.timeoutS)
	}
}

// ─── ClaudeProvider construction ──────────────────────────────────────────────

func TestNewClaudeProvider_Defaults(t *testing.T) {
	p := NewClaudeProvider("plain://key", "", 0)
	if p.ModelDefault() != "claude-sonnet-4-6" {
		t.Errorf("default model: got %q", p.ModelDefault())
	}
}
