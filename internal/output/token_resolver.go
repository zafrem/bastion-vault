package output

import (
	"context"
	"fmt"

	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// TokenResolver converts opaque tokens stored during Phase 1 back to their original
// values, subject to per-tenant and per-user permission checks. It is the only path
// by which Phase 2 surfaces de-anonymized data.
type TokenResolver struct {
	store    tokendb.Store
	kms      kms.Provider
	canDeanon func(user *model.UserContext, category model.DataCategory) bool
}

// NewTokenResolver constructs a resolver. canDeanon is an optional callback that lets
// the processor inject its access-controller check; if nil, every authenticated
// resolution is permitted (use the processor wrapper for production callers).
func NewTokenResolver(store tokendb.Store, provider kms.Provider, canDeanon func(*model.UserContext, model.DataCategory) bool) *TokenResolver {
	return &TokenResolver{
		store:     store,
		kms:       provider,
		canDeanon: canDeanon,
	}
}

// Resolve looks up the original value for a token within tenantID. It returns
// ("", nil) when the token does not exist so callers can choose to keep the
// token in place instead of erroring out.
func (t *TokenResolver) Resolve(ctx context.Context, token string, tenantID string) (string, error) {
	if t.store == nil {
		return "", fmt.Errorf("token resolver: no store configured")
	}
	if token == "" {
		return "", nil
	}
	entry, err := t.store.Get(ctx, token, tenantID)
	if err != nil {
		return "", fmt.Errorf("token resolver: store lookup: %w", err)
	}
	if entry == nil {
		return "", nil
	}
	// Cross-tenant safety net: the store API filters by tenant, but defence-in-depth.
	if entry.TenantID != tenantID {
		return "", fmt.Errorf("token resolver: cross-tenant token rejected")
	}
	return entry.Original, nil
}

// ResolveFields walks every field on the record and replaces any field marked as
// type=="token" with its original value, but only when the user has deanonymize
// rights for the record's category. Other field types are left untouched. The
// record is mutated in place.
func (t *TokenResolver) ResolveFields(ctx context.Context, record *model.DataRecord, user *model.UserContext) error {
	if record == nil || user == nil {
		return fmt.Errorf("token resolver: nil record or user")
	}
	if t.canDeanon != nil && !t.canDeanon(user, record.Category) {
		// Not an error — the caller may be processing many records in mixed
		// permission states. Leave the field as-is.
		return nil
	}
	if record.TenantID != user.TenantID {
		return fmt.Errorf("token resolver: cross-tenant resolution blocked")
	}

	for name, fv := range record.Fields {
		if fv.Type != "token" {
			continue
		}
		tokenStr, ok := fv.Value.(string)
		if !ok {
			tokenStr = fmt.Sprintf("%v", fv.Value)
		}
		original, err := t.Resolve(ctx, tokenStr, record.TenantID)
		if err != nil {
			return fmt.Errorf("token resolver: field %q: %w", name, err)
		}
		if original == "" {
			// Unknown token — keep the masked form rather than leaking the token ID.
			record.Fields[name] = model.FieldValue{
				Value:   "[UNKNOWN_TOKEN]",
				Type:    "anonymized",
				PIIType: fv.PIIType,
			}
			continue
		}
		record.Fields[name] = model.FieldValue{
			Value:   original,
			Type:    "original",
			PIIType: fv.PIIType,
		}
	}
	return nil
}
