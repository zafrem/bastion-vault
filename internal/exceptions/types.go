// Package exceptions implements scoped, expiring exemptions from a block or
// mask decision. Tracker is the authority: it signs every change with an
// Ed25519 key and publishes it; modules verify with the matching public key,
// apply it, and persist the signed envelope locally.
//
// This file is intentionally identical in tracker, sentinel and vault so the
// modules stay independently deployable (no shared library). Keep the copies
// in sync.
package exceptions

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// SubjectUpdates carries signed incremental changes (Tracker -> modules).
	SubjectUpdates = "bastion.exceptions.updates"
	// SubjectSnapshot is a request/reply subject: a module asks, Tracker answers
	// with a signed snapshot of every exception.
	SubjectSnapshot = "bastion.exceptions.snapshot"

	// MaxLifetime bounds how long an exception can last.
	MaxLifetime = 90 * 24 * time.Hour

	minJustification = 10
	signDomain       = "bastion-exceptions-v1\n"
)

// Exception exempts one rule, for one tenant (optionally one user), from
// enforcement by the listed modules until it expires or is revoked.
type Exception struct {
	ID string `json:"id"`
	// Version orders changes to one exception. It is the change time in Unix
	// nanoseconds, so it keeps increasing even if Tracker loses its state.
	Version int64 `json:"version"`
	// Rule is an exact rule identifier such as "sentinel.out.pii:email".
	// Wildcards are not allowed.
	Rule          string    `json:"rule"`
	Modules       []string  `json:"modules"`
	TenantID      string    `json:"tenant_id"`
	UserID        string    `json:"user_id,omitempty"`
	Justification string    `json:"justification"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Revoked       bool      `json:"revoked,omitempty"`
	RevokedBy     string    `json:"revoked_by,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
}

// Payload is the signed content: a set of exception states.
type Payload struct {
	Kind       string      `json:"kind"` // "update" or "snapshot"
	IssuedAt   time.Time   `json:"issued_at"`
	Exceptions []Exception `json:"exceptions"`
}

// Envelope is what travels on the wire and is stored on disk. Payload holds the
// exact signed bytes (base64 in JSON), so verifiers in any language check the
// signature over those bytes with no canonicalisation.
type Envelope struct {
	Payload []byte `json:"payload"`
	Sig     string `json:"sig"`
}

// ParsePublicKeys decodes a comma-separated list of base64 Ed25519 public keys.
// Several keys are accepted so a key can be rotated: list the new and the old
// key together until every issuer has switched.
func ParsePublicKeys(csv string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("exceptions: public key must be a base64 Ed25519 public key")
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// Sign wraps p in a signed envelope.
func Sign(priv ed25519.PrivateKey, p Payload) (Envelope, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, append([]byte(signDomain), raw...))
	return Envelope{Payload: raw, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Verify checks the signature against any of the given public keys and
// decodes the payload.
func Verify(pubs []ed25519.PublicKey, env Envelope) (Payload, error) {
	var p Payload
	if len(pubs) == 0 {
		return p, errors.New("exceptions: no public key configured")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return p, errors.New("exceptions: malformed signature")
	}
	msg := append([]byte(signDomain), env.Payload...)
	ok := false
	for _, pub := range pubs {
		if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return p, errors.New("exceptions: signature verification failed")
	}
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return p, fmt.Errorf("exceptions: bad payload: %w", err)
	}
	return p, nil
}

// ruleExact and rulePrefixes list every rule a module actually enforces. An
// exception for anything else is refused, so nobody can believe a control is
// exempted when nothing honours it, and controls that must never be exempted
// (tenant isolation, Vault permission filtering, the format check) are not here.
var (
	ruleExact = map[string]bool{
		"sentinel.out.permission": true,
		"sentinel.out.grounding":  true,
	}
	rulePrefixes = []string{
		"sentinel.in:", "sentinel.out.pii:", "sentinel.out.content:", "sentinel.industry:",
		"vault.mask:", "vault.view:", "navigator.purpose:", "anchor.bias:",
	}
)

// KnownRule reports whether some module enforces exceptions for rule.
func KnownRule(rule string) bool {
	if ruleExact[rule] {
		return true
	}
	for _, p := range rulePrefixes {
		if strings.HasPrefix(rule, p) && len(rule) > len(p) {
			return true
		}
	}
	return false
}

// Validate checks a new exception before it is issued.
func (e Exception) Validate(now time.Time) error {
	switch {
	case strings.TrimSpace(e.Rule) == "":
		return errors.New("rule is required")
	case strings.ContainsAny(e.Rule, "*?"):
		return errors.New("rule must be an exact identifier; wildcards are not allowed")
	case !KnownRule(strings.TrimSpace(e.Rule)):
		return fmt.Errorf("unknown rule %q: see docs for the rules that can be exempted", e.Rule)
	case len(e.Modules) == 0:
		return errors.New("at least one module is required")
	case strings.TrimSpace(e.TenantID) == "":
		return errors.New("tenant_id is required: exceptions are always scoped to a tenant")
	case len(strings.TrimSpace(e.Justification)) < minJustification:
		return fmt.Errorf("justification must be at least %d characters", minJustification)
	case !e.ExpiresAt.After(now):
		return errors.New("expires_at must be in the future")
	case e.ExpiresAt.After(now.Add(MaxLifetime)):
		return fmt.Errorf("expires_at is more than %d days away", int(MaxLifetime.Hours()/24))
	}
	return nil
}

// Active reports whether the exception can currently be used.
func (e Exception) Active(now time.Time) bool {
	return !e.Revoked && now.Before(e.ExpiresAt)
}

// Applies reports whether the exception exempts this module, rule and caller.
func (e Exception) Applies(module, rule, tenant, user string, now time.Time) bool {
	if !e.Active(now) || e.Rule != rule || e.TenantID == "" || e.TenantID != tenant {
		return false
	}
	if e.UserID != "" && e.UserID != user {
		return false
	}
	for _, m := range e.Modules {
		if m == module {
			return true
		}
	}
	return false
}
