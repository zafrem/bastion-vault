package strategies

import "context"

// Strategy applies a single anonymization technique to a field value.
// All implementations must be safe for concurrent use.
type Strategy interface {
	// Apply transforms a plaintext value into its anonymized form.
	Apply(ctx context.Context, value string, params Params) (string, error)

	// Reverse undoes Apply for reversible strategies; returns ErrNotReversible
	// for one-way transformations.
	Reverse(ctx context.Context, value string, params Params) (string, error)

	// Name returns the canonical strategy identifier used in audit logs.
	Name() string

	// Reversible reports whether this strategy can reconstruct the original value.
	Reversible() bool
}

// Params bundles the keying material and field-specific options for a strategy call.
type Params struct {
	// HMACKey is the 32-byte key used for HMAC and tokenization strategies.
	HMACKey []byte

	// EncryptionKey is the 32-byte AES-256 key used by the encryption strategy.
	EncryptionKey []byte

	// MaskPattern describes how partial masking should be applied (e.g. "010-****-{last4}").
	MaskPattern string

	// GeneralizationLevel controls how far up the hierarchy to generalize (0 = finest).
	GeneralizationLevel int

	// Domain carries extra context (e.g. the email domain to preserve).
	Domain string

	// FieldHint carries the field name so strategies can pick appropriate defaults.
	FieldHint string
}

// ErrNotReversible is returned when Reverse is called on a one-way strategy.
type ErrNotReversible struct{ Strategy string }

func (e ErrNotReversible) Error() string {
	return e.Strategy + ": strategy is not reversible"
}
