package model

import "time"

// contextKey is an unexported type for context keys in this package to avoid collisions.
type contextKey string

// UserContextKey is the key used to store and retrieve a *User from a request context.
const UserContextKey contextKey = "vault_user"

// DataCategory identifies the classification of a data set per SRS §3.1
type DataCategory string

const (
	CategoryCustomer      DataCategory = "DC-01"
	CategoryManufacturing DataCategory = "DC-02"
	CategoryHRFinance     DataCategory = "DC-03"
)

// PIIType identifies the kind of personally identifiable information
type PIIType string

const (
	PIIKoreanName   PIIType = "korean_name"
	PIIKoreanRRN    PIIType = "korean_rrn"
	PIIKoreanMobile PIIType = "korean_mobile"
	PIIEmail        PIIType = "email"
	PIIAddressCity  PIIType = "address_city"
	PIIAddressDetail PIIType = "address_detail"
	PIICreditCard   PIIType = "credit_card"
	PIIDateOfBirth  PIIType = "date_of_birth"
	PIISalary       PIIType = "salary"
	PIIWorkerID     PIIType = "worker_id"
	PIIProductCode  PIIType = "product_code"
	PIIEmployeeID   PIIType = "employee_id"
)

// SensitivityLevel reflects the L1–L5 classification from SRS §3.2
type SensitivityLevel int

const (
	SensitivityL1DirectIdentifier   SensitivityLevel = 1 // RRN, SSN, email
	SensitivityL2IndirectIdentifier SensitivityLevel = 2 // name, phone
	SensitivityL3SensitivePersonal  SensitivityLevel = 3 // medical, religion
	SensitivityL4QuasiIdentifier    SensitivityLevel = 4 // age, gender, region
	SensitivityL5Public             SensitivityLevel = 5 // employee ID, department
)

// AnonymizationStrategy names the technique applied to a PII field
type AnonymizationStrategy string

const (
	StrategyDeterministicTokenization AnonymizationStrategy = "deterministic_tokenization"
	StrategyHMACSHA256                AnonymizationStrategy = "hmac_sha256"
	StrategyPartialMasking            AnonymizationStrategy = "partial_masking"
	StrategyFPEEmail                  AnonymizationStrategy = "fpe_email"
	StrategySuppression               AnonymizationStrategy = "suppression"
	StrategyGeneralization            AnonymizationStrategy = "generalization"
	StrategyRangeGeneralization       AnonymizationStrategy = "range_generalization"
	StrategyEncryption                AnonymizationStrategy = "encryption"
)

// AccessLevel represents the privilege tier for data access
type AccessLevel string

const (
	AccessFull        AccessLevel = "full"
	AccessRead        AccessLevel = "read"
	AccessAnonymized  AccessLevel = "anonymized"
	AccessKAnonymized AccessLevel = "k_anonymized"
	AccessSlice       AccessLevel = "slice"
	AccessAggregated  AccessLevel = "aggregated"
	AccessAuditLog    AccessLevel = "audit_log"
	AccessNone        AccessLevel = "none"
)

// AccessLevelFromString converts a string to an AccessLevel constant.
// Returns AccessNone for unknown strings.
func AccessLevelFromString(s string) AccessLevel {
	switch s {
	case "full":
		return AccessFull
	case "read":
		return AccessRead
	case "anonymized":
		return AccessAnonymized
	case "k_anonymized":
		return AccessKAnonymized
	case "slice":
		return AccessSlice
	case "aggregated":
		return AccessAggregated
	case "audit_log":
		return AccessAuditLog
	default:
		return AccessNone
	}
}

// AccessLevelRank returns a numeric rank; higher = more privileged
func AccessLevelRank(l AccessLevel) int {
	ranks := map[AccessLevel]int{
		AccessFull:        7,
		AccessRead:        6,
		AccessAnonymized:  5,
		AccessKAnonymized: 4,
		AccessSlice:       3,
		AccessAggregated:  2,
		AccessAuditLog:    1,
		AccessNone:        0,
	}
	return ranks[l]
}

// PIIDetection holds the result of detecting a single PII occurrence
type PIIDetection struct {
	Field      string           `json:"field"`
	PIIType    PIIType          `json:"pii_type"`
	Confidence float64          `json:"confidence"`
	Sensitivity SensitivityLevel `json:"sensitivity_level"`
}

// ClassificationResult is returned by the classifier for a data record
type ClassificationResult struct {
	Category       DataCategory   `json:"category"`
	Detections     []PIIDetection `json:"detections"`
	KThreshold     int            `json:"k_threshold"`
	Recommendation string         `json:"recommendation"`
}

// AnonymizeRequest is the input to the anonymization engine
type AnonymizeRequest struct {
	TenantID   string                 `json:"tenant_id"`
	Category   DataCategory           `json:"category"`
	Records    []map[string]any       `json:"records"`
	Purpose    string                 `json:"purpose"`
	RequesterID string               `json:"requester_id"`
	AccessLevel AccessLevel          `json:"access_level"`
	BreakGlassToken string           `json:"break_glass_token,omitempty"`
}

// AnonymizeResponse is returned by the anonymization engine
type AnonymizeResponse struct {
	TenantID  string           `json:"tenant_id"`
	Category  DataCategory     `json:"category"`
	Records   []map[string]any `json:"records"`
	AuditID   string           `json:"audit_id"`
	Metadata  AnonymizeMetadata `json:"metadata"`
}

// AnonymizeMetadata contains statistics about the anonymization run
type AnonymizeMetadata struct {
	RecordCount       int                            `json:"record_count"`
	FieldsAnonymized  int                            `json:"fields_anonymized"`
	StrategiesApplied map[string]int                 `json:"strategies_applied"`
	KAnonymityValid   bool                           `json:"k_anonymity_valid"`
	ProcessedAt       time.Time                      `json:"processed_at"`
}

// DeanonymizeRequest requests reversal of anonymization for reversible fields
type DeanonymizeRequest struct {
	TenantID    string           `json:"tenant_id"`
	Category    DataCategory     `json:"category"`
	Records     []map[string]any `json:"records"`
	RequesterID string           `json:"requester_id"`
	Justification string         `json:"justification"`
}

// KAnonymityReport is returned by the k-anonymity validator
type KAnonymityReport struct {
	Valid              bool                `json:"valid"`
	K                  int                 `json:"k"`
	RequiredK          int                 `json:"required_k"`
	Violations         []KAnonymityViolation `json:"violations,omitempty"`
	GeneralizationSteps []GeneralizationStep `json:"generalization_steps,omitempty"`
}

// KAnonymityViolation describes a single quasi-identifier group that is too small
type KAnonymityViolation struct {
	QuasiIdentifiers map[string]any `json:"quasi_identifiers"`
	GroupSize        int            `json:"group_size"`
	RequiredSize     int            `json:"required_size"`
}

// GeneralizationStep records one hierarchy step applied during auto-generalization
type GeneralizationStep struct {
	Field   string `json:"field"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// BreakGlassRequest is the initial request for emergency elevated access
type BreakGlassRequest struct {
	ID          string        `json:"id"`
	RequesterID string        `json:"requester_id"`
	IncidentID  string        `json:"incident_id"`
	Reason      string        `json:"reason"`
	Duration    time.Duration `json:"duration"`
	DataCategory DataCategory `json:"data_category"`
	Status      BreakGlassStatus `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	Approvers   []string      `json:"approvers"`
	Token       string        `json:"token,omitempty"`
}

// BreakGlassStatus represents the lifecycle state of a break-glass request
type BreakGlassStatus string

const (
	BGStatusPending  BreakGlassStatus = "pending"
	BGStatusApproved BreakGlassStatus = "approved"
	BGStatusActive   BreakGlassStatus = "active"
	BGStatusRevoked  BreakGlassStatus = "revoked"
	BGStatusExpired  BreakGlassStatus = "expired"
)

// AuditEvent is the immutable record written for every sensitive operation
type AuditEvent struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenant_id"`
	Timestamp    time.Time        `json:"timestamp"`
	EventType    AuditEventType   `json:"event_type"`
	ActorID      string           `json:"actor_id"`
	ResourceType string           `json:"resource_type"`
	ResourceID   string           `json:"resource_id"`
	Action       string           `json:"action"`
	Outcome      string           `json:"outcome"`
	Metadata     map[string]any   `json:"metadata,omitempty"`
	Signature    string           `json:"signature,omitempty"`
	BreakGlass   bool             `json:"break_glass"`
}

// AuditEventType categorises the audit record
type AuditEventType string

const (
	AuditEventAnonymize    AuditEventType = "anonymize"
	AuditEventDeanonymize  AuditEventType = "deanonymize"
	AuditEventAccess       AuditEventType = "access"
	AuditEventBreakGlass   AuditEventType = "break_glass"
	AuditEventKMSOperation AuditEventType = "kms_operation"
	AuditEventPolicyCheck  AuditEventType = "policy_check"
	AuditEventErasure      AuditEventType = "erasure"
)

// User carries identity and role information for access control decisions
type User struct {
	UserID     string            `json:"user_id"`
	ID         string            `json:"id"` // deprecated: use UserID
	TenantID   string            `json:"tenant_id"`
	Department string            `json:"department"`
	Role       string            `json:"role"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// AccessDecision is the result of an OPA policy evaluation
type AccessDecision struct {
	Allowed     bool        `json:"allowed"`
	AccessLevel AccessLevel `json:"access_level"`
	Reason      string      `json:"reason"`
	Conditions  []string    `json:"conditions,omitempty"`
}

// TenantConfig holds per-tenant customization
type TenantConfig struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	KMSKeyID      string            `json:"kms_key_id"`
	HMACKeyID     string            `json:"hmac_key_id"`
	AuditKeyID    string            `json:"audit_key_id"`
	CustomPolicies map[string]any   `json:"custom_policies,omitempty"`
}
