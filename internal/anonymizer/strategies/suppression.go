package strategies

import "context"

const suppressionPlaceholder = "[REMOVED]"

// SuppressionStrategy replaces the entire field value with "[REMOVED]".
// Used for address_detail per SRS §3.3 where even partial disclosure is prohibited.
type SuppressionStrategy struct{}

func NewSuppression() *SuppressionStrategy { return &SuppressionStrategy{} }

func (s *SuppressionStrategy) Name() string     { return "suppression" }
func (s *SuppressionStrategy) Reversible() bool { return false }

func (s *SuppressionStrategy) Apply(_ context.Context, _ string, _ Params) (string, error) {
	return suppressionPlaceholder, nil
}

func (s *SuppressionStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}
