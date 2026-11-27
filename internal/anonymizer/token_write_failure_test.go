package anonymizer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

var errStoreDown = errors.New("token store is down")

type brokenStore struct{ tokendb.Store }

func (brokenStore) Put(context.Context, tokendb.Entry) error { return errStoreDown }

// A token whose mapping was not saved can never be reversed, so the request must fail instead of returning it.
func TestAnonymize_FailsWhenTheTokenCannotBeSaved(t *testing.T) {
	provider, err := kms.NewLocalProvider(t.TempDir(), testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	eng := NewEngine(kms.NewManager(provider, time.Minute), classification.New(), aud, brokenStore{tokendb.NewMemoryStore()})

	for name, record := range map[string]map[string]any{
		"tokenized field":           {"email": "hong@example.com"},
		"masked field search token": {"mobile": "010-1234-5678"},
	} {
		resp, err := eng.Anonymize(context.Background(), &model.AnonymizeRequest{
			TenantID: "t1", Category: model.CategoryCustomer, RequesterID: "tester", Records: []map[string]any{record},
		})
		if !errors.Is(err, errStoreDown) {
			t.Errorf("%s: want the store error, got err=%v response=%+v", name, err, resp)
		}
	}
}
