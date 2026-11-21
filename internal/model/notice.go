package model

// UserNotice tells the end user that data was masked or blocked, and why, in
// terms that are safe to show. It never carries the values themselves; the
// detailed reasons stay in the audit log and the Tracker.
type UserNotice struct {
	Action      string `json:"action"` // "masked" or "blocked"
	Code        string `json:"code"`
	Message     string `json:"message"`
	ReferenceID string `json:"reference_id,omitempty"` // audit ID, to find the record
	Count       int    `json:"count,omitempty"`        // how many fields were masked
}

// Notice codes and detail levels, kept identical to Sentinel's so one front
// end can render notices from either module.
const (
	NoticeMasked      = "masked"
	CodePIIRedacted   = "PII_REDACTED"
	CodeResponseMod   = "RESPONSE_MODIFIED"
	NoticeDetailMin   = "minimal"
	NoticeDetailCateg = "category"
)

// NewMaskedNotice builds the notice for a request in which count fields were masked.
func NewMaskedNotice(detail, referenceID string, count int) *UserNotice {
	if count <= 0 {
		return nil
	}
	if detail == NoticeDetailMin {
		return &UserNotice{Action: NoticeMasked, Code: CodeResponseMod, ReferenceID: referenceID,
			Message: "Your request was modified before it was processed."}
	}
	return &UserNotice{Action: NoticeMasked, Code: CodePIIRedacted, ReferenceID: referenceID, Count: count,
		Message: "Some personal information in your request was replaced with placeholders before it was processed."}
}
