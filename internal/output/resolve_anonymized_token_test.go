package output

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// What anonymize hands out is what callers send back to resolve-tokens.
func TestResolveTokens_AcceptsTheTokenAsAnonymizeReturnsIt(t *testing.T) {
	provider, err := kms.NewLocalProvider(t.TempDir(), "0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	store, ctx := tokendb.NewMemoryStore(), context.Background()

	eng := anonymizer.NewEngine(kms.NewManager(provider, time.Minute), classification.New(), aud, store)
	resp, err := eng.Anonymize(ctx, &model.AnonymizeRequest{
		TenantID: "t1", Category: model.CategoryCustomer, RequesterID: "tester",
		Records: []map[string]any{{"email": "hong@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	returned := resp.Records[0]["email"].(string)

	proc := NewProcessor(access.NewController(""), aud, store, provider)
	user := &model.UserContext{UserID: "u", TenantID: "t1", Department: "marketing", Roles: []string{"manager"}}
	for name, token := range map[string]string{"as returned": returned, "without the prefix": strings.TrimPrefix(returned, "TOK:")} {
		got, err := proc.ResolveTokens(ctx, []model.DataRecord{{RecordID: "1", TenantID: "t1", Category: model.CategoryCustomer,
			Fields: map[string]model.FieldValue{"email": {Value: token, Type: "token"}}}}, user)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f := got[0].Fields["email"]; f.Value != "hong@example.com" || f.Type != "original" {
			t.Errorf("%s (%q): got %+v", name, token, f)
		}
	}
}
