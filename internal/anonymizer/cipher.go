package anonymizer

import (
	"context"
	"fmt"

	"github.com/zafrem/bastion-vault/internal/envelope"
	"github.com/zafrem/bastion-vault/internal/model"
)

// masterKeyID names the KMS key for one tenant's data of one category.
func masterKeyID(tenantID string, cat model.DataCategory) string {
	return fmt.Sprintf("tenant:%s:category:%s", tenantID, string(cat))
}

// fieldCipher encrypts field values for one tenant and category. Both are authenticated with the value:
// permission to decrypt is granted per tenant and category, and some key providers unwrap a data key without
// looking at which key id was asked for.
type fieldCipher struct {
	sealer *envelope.Sealer
	keyID  string
	bound  []byte
}

func (e *Engine) cipherFor(tenantID string, cat model.DataCategory) fieldCipher {
	return fieldCipher{
		sealer: e.sealer,
		keyID:  masterKeyID(tenantID, cat),
		bound:  []byte(fmt.Sprintf("enc:v1|%d:%s|%d:%s", len(tenantID), tenantID, len(cat), cat)),
	}
}

func (c fieldCipher) Encrypt(ctx context.Context, plain []byte) ([]byte, error) {
	return c.sealer.Seal(ctx, c.keyID, c.bound, plain)
}

func (c fieldCipher) Decrypt(ctx context.Context, sealed []byte) ([]byte, error) {
	return c.sealer.Open(ctx, c.keyID, c.bound, sealed)
}
