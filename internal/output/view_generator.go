package output

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/zafrem/bastion-vault/internal/model"
)

// pseudonymKey is a process-stable key used for HMAC-based pseudonymization in the
// `anonymized` view. A production deployment would derive this from KMS; we use a
// stable per-process key so output is consistent within a session and never reveals
// the underlying token.
var pseudonymKey = []byte("vault-out-anonymized-view-key-v1")

// sliceManufacturingAllowed lists the only fields a manufacturing user may see for
// customer-data records (FR-SA-002).
var sliceManufacturingAllowed = map[string]bool{
	"product_id":     true,
	"complaint_type": true,
	"region":         true,
	"date":           true,
}

// sliceManufacturingBlocked lists fields that must NEVER appear in a manufacturing
// slice view, even if their name was not enumerated in the allow-list.
var sliceManufacturingBlocked = map[string]bool{
	"name":     true,
	"contact":  true,
	"address":  true,
	"payment":  true,
	"salary":   true,
	"rrn":      true,
	"email":    true,
	"mobile":   true,
}

// sensitiveFieldsForRead are masked even at the `read` level — the user sees the
// record but the highest-sensitivity identifiers stay hidden.
var sensitiveFieldsForRead = map[string]bool{
	"rrn":              true,
	"social_security":  true,
	"credit_card":      true,
}

// ViewGenerator applies per-access-level transformations to a slice of DataRecords.
// It is stateless and safe for concurrent use.
type ViewGenerator struct{}

// NewViewGenerator constructs a ViewGenerator.
func NewViewGenerator() *ViewGenerator {
	return &ViewGenerator{}
}

// Generate transforms records into the view appropriate for the given access level
// and user context. It returns the transformed records and a per-field disclosure
// audit trail. On error the function returns no records and no disclosures.
//
// Unknown access levels fail-safe to the most restrictive view ("[HIDDEN]" for every
// field) so a configuration or wiring bug can never accidentally expose data.
func (g *ViewGenerator) Generate(
	_ context.Context,
	records []model.DataRecord,
	user *model.UserContext,
	level model.AccessLevel,
) ([]model.DataRecord, []model.FieldDisclosure, error) {
	if user == nil {
		return nil, nil, fmt.Errorf("view generator: nil user context")
	}

	out := make([]model.DataRecord, 0, len(records))
	var disclosures []model.FieldDisclosure

	for _, rec := range records {
		transformed, recDisclosures := g.transformRecord(rec, user, level)
		out = append(out, transformed)
		disclosures = append(disclosures, recDisclosures...)
	}

	return out, disclosures, nil
}

// transformRecord applies the per-level transformation to a single record.
func (g *ViewGenerator) transformRecord(
	rec model.DataRecord,
	user *model.UserContext,
	level model.AccessLevel,
) (model.DataRecord, []model.FieldDisclosure) {
	out := model.DataRecord{
		RecordID: rec.RecordID,
		Category: rec.Category,
		TenantID: rec.TenantID,
		Fields:   make(map[string]model.FieldValue, len(rec.Fields)),
	}
	var disclosures []model.FieldDisclosure

	for name, fv := range rec.Fields {
		newFV, disc := g.transformField(name, fv, user, level)
		out.Fields[name] = newFV
		disclosures = append(disclosures, model.FieldDisclosure{
			FieldName:     name,
			OriginalState: fv.Type,
			FinalState:    newFV.Type,
			Reason:        disc,
		})
	}

	return out, disclosures
}

// transformField returns the field's transformed value plus the human-readable
// reason that drove the decision (used for audit and UI explainability).
func (g *ViewGenerator) transformField(
	name string,
	fv model.FieldValue,
	user *model.UserContext,
	level model.AccessLevel,
) (model.FieldValue, string) {
	switch level {
	case model.AccessFull:
		return fv, "full access granted"

	case model.AccessRead:
		// Original values, but mask the most sensitive direct identifiers.
		if sensitiveFieldsForRead[strings.ToLower(name)] {
			return model.FieldValue{
				Value:   "[MASKED]",
				Type:    "masked",
				PIIType: fv.PIIType,
			}, "read access masks high-sensitivity identifier"
		}
		// Strip raw tokens — read-only callers see meaningful values, not internal IDs.
		if fv.Type == "token" {
			return model.FieldValue{
				Value:   "[TOKEN_STRIPPED]",
				Type:    "anonymized",
				PIIType: fv.PIIType,
			}, "tokens not exposed at read level"
		}
		return fv, "read access — original value"

	case model.AccessAnonymized:
		return g.anonymizeField(name, fv, user)

	case model.AccessKAnonymized:
		return g.kAnonymizeField(name, fv)

	case model.AccessSlice:
		return g.sliceField(name, fv, user)

	case model.AccessAggregated:
		// Aggregation is handled at the set level; per-record fields are suppressed.
		return model.FieldValue{
			Value: "[AGGREGATED]",
			Type:  "aggregated",
		}, "individual records suppressed under aggregated access"

	case model.AccessAuditLog:
		// Audit-log users may not see record contents — only metadata at the
		// processor level. Per-field values are hidden.
		return model.FieldValue{
			Value: "[AUDIT_ONLY]",
			Type:  "hidden",
		}, "audit_log access — record contents withheld"

	default:
		// Fail-safe: unknown level = most restrictive view.
		return model.FieldValue{
			Value: "[HIDDEN]",
			Type:  "hidden",
		}, "fail-safe: unknown access level"
	}
}

// anonymizeField applies HMAC-based pseudonymization to name/contact/address fields
// and suppresses everything else. The pseudonym is stable for the same input so
// downstream joins still work, but the original value cannot be recovered.
func (g *ViewGenerator) anonymizeField(name string, fv model.FieldValue, user *model.UserContext) (model.FieldValue, string) {
	lower := strings.ToLower(name)
	pseudonymizable := strings.Contains(lower, "name") ||
		strings.Contains(lower, "contact") ||
		strings.Contains(lower, "email") ||
		strings.Contains(lower, "phone") ||
		strings.Contains(lower, "mobile") ||
		strings.Contains(lower, "address")

	if pseudonymizable {
		mac := hmac.New(sha256.New, pseudonymKey)
		mac.Write([]byte(user.TenantID))
		mac.Write([]byte(":"))
		mac.Write([]byte(fmt.Sprintf("%v", fv.Value)))
		sum := hex.EncodeToString(mac.Sum(nil))[:16]
		return model.FieldValue{
			Value:   "PSEUDO_" + sum,
			Type:    "anonymized",
			PIIType: fv.PIIType,
		}, "anonymized: HMAC pseudonym applied"
	}

	// Non-identifier numeric / categorical fields pass through unchanged so that
	// analytics remain meaningful. The exception: anything previously encrypted
	// stays encrypted (we do not have decryption rights at this level).
	if fv.Type == "encrypted" {
		return model.FieldValue{
			Value: "[ENCRYPTED]",
			Type:  "encrypted",
		}, "anonymized: encrypted field not unwrapped"
	}
	return fv, "anonymized: non-identifier passthrough"
}

// kAnonymizeField applies generalization to quasi-identifiers. The set-level
// k-threshold check is enforced separately in the Processor.
func (g *ViewGenerator) kAnonymizeField(name string, fv model.FieldValue) (model.FieldValue, string) {
	lower := strings.ToLower(name)

	// Hide direct identifiers outright.
	if strings.Contains(lower, "name") ||
		strings.Contains(lower, "rrn") ||
		strings.Contains(lower, "ssn") ||
		strings.Contains(lower, "phone") ||
		strings.Contains(lower, "mobile") ||
		strings.Contains(lower, "contact") {
		return model.FieldValue{
			Value:   "[ANONYMIZED]",
			Type:    "anonymized",
			PIIType: fv.PIIType,
		}, "k_anonymized: direct identifier hidden"
	}

	// Email → domain only.
	if strings.Contains(lower, "email") {
		s := fmt.Sprintf("%v", fv.Value)
		if at := strings.Index(s, "@"); at >= 0 && at < len(s)-1 {
			return model.FieldValue{
				Value:   s[at+1:],
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "k_anonymized: email domain only"
		}
		return model.FieldValue{Value: "[ANONYMIZED]", Type: "anonymized", PIIType: fv.PIIType},
			"k_anonymized: email anonymized"
	}

	// Address / region → province (first whitespace-delimited token).
	if strings.Contains(lower, "address") || strings.Contains(lower, "region") {
		s := fmt.Sprintf("%v", fv.Value)
		if parts := strings.Fields(s); len(parts) > 0 {
			return model.FieldValue{
				Value:   parts[0],
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "k_anonymized: region generalized to province"
		}
		return fv, "k_anonymized: region passthrough (no whitespace)"
	}

	// Dates → month only (YYYY-MM).
	if strings.Contains(lower, "date") || strings.Contains(lower, "birth") {
		s := fmt.Sprintf("%v", fv.Value)
		if t, err := time.Parse("2006-01-02", s); err == nil {
			return model.FieldValue{
				Value:   t.Format("2006-01"),
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "k_anonymized: date generalized to month"
		}
		if len(s) >= 7 {
			return model.FieldValue{
				Value:   s[:7],
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "k_anonymized: date trimmed to month"
		}
	}

	// Encrypted values remain wrapped.
	if fv.Type == "encrypted" {
		return model.FieldValue{Value: "[ENCRYPTED]", Type: "encrypted"},
			"k_anonymized: encrypted field stays sealed"
	}

	return fv, "k_anonymized: quasi-identifier passthrough"
}

// sliceField enforces manufacturing-style slice access: only the explicitly allowed
// fields appear, blocked fields are scrubbed, and the rest are filtered out.
func (g *ViewGenerator) sliceField(name string, fv model.FieldValue, user *model.UserContext) (model.FieldValue, string) {
	lower := strings.ToLower(name)

	if sliceManufacturingBlocked[lower] {
		return model.FieldValue{
			Value: "[BLOCKED]",
			Type:  "filtered",
		}, "slice: field explicitly blocked"
	}

	if !sliceManufacturingAllowed[lower] {
		return model.FieldValue{
			Value: "[NOT_IN_SLICE]",
			Type:  "filtered",
		}, "slice: field outside allowed set"
	}

	// Allowed slice fields receive generalization where appropriate.
	if lower == "region" {
		s := fmt.Sprintf("%v", fv.Value)
		if parts := strings.Fields(s); len(parts) > 0 {
			return model.FieldValue{
				Value:   parts[0],
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "slice: region generalized to province"
		}
	}
	if lower == "date" {
		s := fmt.Sprintf("%v", fv.Value)
		if t, err := time.Parse("2006-01-02", s); err == nil {
			return model.FieldValue{
				Value:   t.Format("2006-01"),
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "slice: date generalized to month"
		}
		if len(s) >= 7 {
			return model.FieldValue{
				Value:   s[:7],
				Type:    "generalized",
				PIIType: fv.PIIType,
			}, "slice: date trimmed to month"
		}
	}

	_ = user // reserved for future slice-context-specific generalization rules
	return fv, "slice: field allowed"
}
