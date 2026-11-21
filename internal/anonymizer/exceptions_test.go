package anonymizer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/exceptions"
	"github.com/zafrem/bastion-vault/internal/model"
)

func excEngine(t *testing.T) (*Engine, func(rule, tenant string, revoked bool, version int64)) {
	t.Helper()
	eng, _ := newTestEngine(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := exceptions.NewClient("vault", base64.StdEncoding.EncodeToString(pub), filepath.Join(t.TempDir(), "e.json"))
	if err != nil {
		t.Fatal(err)
	}
	eng.SetExceptions(c)
	return eng, func(rule, tenant string, revoked bool, version int64) {
		env, err := exceptions.Sign(priv, exceptions.Payload{Kind: "update", IssuedAt: time.Now(),
			Exceptions: []exceptions.Exception{{ID: "exc-v1", Version: version, Rule: rule, Modules: []string{"vault"},
				TenantID: tenant, ExpiresAt: time.Now().Add(time.Hour), Revoked: revoked}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Apply(env); err != nil {
			t.Fatal(err)
		}
	}
}

func emailRequest(tenant string) *model.AnonymizeRequest {
	return &model.AnonymizeRequest{
		TenantID: tenant, Category: model.CategoryCustomer, RequesterID: "u1",
		Records:     []map[string]any{{"email": "hong@example.com"}},
		AccessLevel: model.AccessAnonymized,
	}
}

func emailOut(t *testing.T, eng *Engine, tenant string) (*model.AnonymizeResponse, string) {
	t.Helper()
	resp, err := eng.Anonymize(context.Background(), emailRequest(tenant))
	if err != nil {
		t.Fatal(err)
	}
	return resp, resp.Records[0]["email"].(string)
}

func TestNotice_ReportsMaskingWithoutValues(t *testing.T) {
	eng, _ := newTestEngine(t)
	resp, out := emailOut(t, eng, "acme")
	if out == "hong@example.com" {
		t.Fatal("setup: email should be masked")
	}
	n := resp.Notice
	if n == nil || n.Action != model.NoticeMasked || n.Code != model.CodePIIRedacted || n.Count < 1 || n.ReferenceID == "" {
		t.Fatalf("expected a masked notice with count and reference, got %+v", n)
	}
	eng.SetNoticeDetail(model.NoticeDetailMin)
	if n := mustNotice(t, eng); n.Code != model.CodeResponseMod || n.Count != 0 {
		t.Errorf("minimal notice must be generic: %+v", n)
	}
}

func mustNotice(t *testing.T, eng *Engine) *model.UserNotice {
	t.Helper()
	resp, _ := emailOut(t, eng, "acme")
	if resp.Notice == nil {
		t.Fatal("no notice")
	}
	return resp.Notice
}

func TestException_LeavesFieldUnmaskedForTenantOnly(t *testing.T) {
	eng, issue := excEngine(t)
	issue("vault.mask:"+string(model.PIIEmail), "acme", false, 1)

	resp, out := emailOut(t, eng, "acme")
	if out != "hong@example.com" {
		t.Fatalf("exempted tenant should keep the email, got %q", out)
	}
	if len(resp.ExceptionsApplied) != 1 || resp.ExceptionsApplied[0] != "exc-v1" {
		t.Errorf("exception use must be reported: %v", resp.ExceptionsApplied)
	}
	if _, other := emailOut(t, eng, "globex"); other == "hong@example.com" {
		t.Error("another tenant must still be masked")
	}
}

func TestException_RevocationRestoresMasking(t *testing.T) {
	eng, issue := excEngine(t)
	rule := "vault.mask:" + string(model.PIIEmail)
	issue(rule, "acme", false, 1)
	if _, out := emailOut(t, eng, "acme"); out != "hong@example.com" {
		t.Fatal("setup: exception should be active")
	}
	issue(rule, "acme", true, 2)
	if _, out := emailOut(t, eng, "acme"); out == "hong@example.com" {
		t.Error("after revocation the email must be masked again")
	}
}

func TestWorksWithNoExceptionStore(t *testing.T) {
	eng, _ := newTestEngine(t) // no SetExceptions: standalone
	if _, out := emailOut(t, eng, "acme"); out == "hong@example.com" {
		t.Error("with no exceptions configured every field must be masked")
	}
}
