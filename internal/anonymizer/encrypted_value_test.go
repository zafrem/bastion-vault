package anonymizer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

const otherMasterKey = "0000000000000000000000000000000000000000000000000000000000000002"

// engineWith builds an engine as a fresh process would: its own KMS manager and no cached keys.
func engineWith(t *testing.T, masterKey string, keyTTL time.Duration) *Engine {
	t.Helper()
	provider, err := kms.NewLocalProvider(t.TempDir(), masterKey)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	return NewEngine(kms.NewManager(provider, keyTTL), classification.New(), aud, tokendb.NewMemoryStore())
}

func encryptSalary(t *testing.T, eng *Engine, tenant, salary string) string {
	t.Helper()
	resp, err := eng.Anonymize(context.Background(), &model.AnonymizeRequest{
		TenantID: tenant, Category: model.CategoryHRFinance, RequesterID: "tester",
		Records: []map[string]any{{"salary": salary}},
	})
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	v, _ := resp.Records[0]["salary"].(string)
	if !strings.HasPrefix(v, "ENC:") || strings.Contains(v, salary) {
		t.Fatalf("salary was not encrypted: %q", v)
	}
	return v
}

func decryptSalary(eng *Engine, tenant string, category model.DataCategory, value string) (string, error) {
	resp, err := eng.Deanonymize(context.Background(), &model.DeanonymizeRequest{
		TenantID: tenant, Category: category, RequesterID: "tester",
		Records: []map[string]any{{"salary": value}},
	})
	if err != nil {
		return "", err
	}
	v, _ := resp.Records[0]["salary"].(string)
	return v, nil
}

func TestEncryptedValue_SurvivesARestart(t *testing.T) {
	enc := encryptSalary(t, engineWith(t, testMasterKey, time.Minute), "t1", "99000000")

	got, err := decryptSalary(engineWith(t, testMasterKey, time.Minute), "t1", model.CategoryHRFinance, enc)
	if err != nil || got != "99000000" {
		t.Fatalf("after a restart: got %q, %v", got, err)
	}
}

func TestEncryptedValue_SurvivesKeyCacheExpiry(t *testing.T) {
	eng := engineWith(t, testMasterKey, time.Nanosecond) // every key is stale as soon as it is cached
	first := encryptSalary(t, eng, "t1", "11111111")
	second := encryptSalary(t, eng, "t1", "22222222")
	for value, want := range map[string]string{first: "11111111", second: "22222222"} {
		if got, err := decryptSalary(eng, "t1", model.CategoryHRFinance, value); err != nil || got != want {
			t.Errorf("after the data key expired: got %q, %v; want %q", got, err, want)
		}
	}
}

// Deanonymize permission is granted per tenant and category, so a value must only open under the pair it was
// encrypted for.
func TestEncryptedValue_OpensOnlyForItsTenantCategoryAndMasterKey(t *testing.T) {
	eng := engineWith(t, testMasterKey, time.Minute)
	enc := encryptSalary(t, eng, "t1", "99000000")

	for name, try := range map[string]func() (string, error){
		"another tenant":   func() (string, error) { return decryptSalary(eng, "t2", model.CategoryHRFinance, enc) },
		"another category": func() (string, error) { return decryptSalary(eng, "t1", model.CategoryCustomer, enc) },
		"another master key": func() (string, error) {
			return decryptSalary(engineWith(t, otherMasterKey, time.Minute), "t1", model.CategoryHRFinance, enc)
		},
		"altered value": func() (string, error) {
			b := []byte(enc)
			i := len(b) - 5
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			return decryptSalary(eng, "t1", model.CategoryHRFinance, string(b))
		},
		"truncated value": func() (string, error) { return decryptSalary(eng, "t1", model.CategoryHRFinance, enc[:14]) },
	} {
		if got, err := try(); err == nil {
			t.Errorf("%s: want an error, got %q", name, got)
		}
	}
}

// Values from earlier versions cannot be recovered (their key was never saved). The error has to say so.
func TestEncryptedValue_FromAnEarlierVersionIsExplained(t *testing.T) {
	_, err := decryptSalary(engineWith(t, testMasterKey, time.Minute), "t1", model.CategoryHRFinance,
		"ENC:D-JotXs8b2PNLSoKVkfS9dfDBhOKVmeJydqXilq2_679")
	if err == nil || !strings.Contains(err.Error(), "earlier version") {
		t.Errorf("want an explanation naming the earlier version, got %v", err)
	}
}
