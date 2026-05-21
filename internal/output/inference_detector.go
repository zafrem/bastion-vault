package output

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/model"
)

// Inference detection thresholds per SRS §4.6 (FR-IA-003).
const (
	inferenceWarnThreshold       = 0.3
	inferenceGeneralizeThreshold = 0.6
	inferenceBlockThreshold      = 0.8

	inferenceMaxHistory = 50
	inferenceWindow     = time.Hour
)

// QueryRecord captures a single query for inference-attack analysis.
type QueryRecord struct {
	Timestamp   time.Time
	Category    model.DataCategory
	FieldCount  int
	ResultCount int
	Specificity float64
}

// QueryParams describes the current query under evaluation.
type QueryParams struct {
	Category            model.DataCategory
	Filters             map[string]string
	ExpectedResultCount int
}

// InferenceDetector tracks per-user query history and produces a risk score that
// classifies the current query as allow / warn / generalize / block.
// Histories live in-memory (sync.Map). The detector keeps at most inferenceMaxHistory
// records per user and prunes anything older than inferenceWindow.
type InferenceDetector struct {
	history sync.Map // userID -> *userHistory
}

type userHistory struct {
	mu      sync.Mutex
	records []QueryRecord
}

// NewInferenceDetector returns a fresh detector with empty per-user histories.
func NewInferenceDetector() *InferenceDetector {
	return &InferenceDetector{}
}

// Detect computes the risk score for the supplied query and returns the recommended
// action. The query is recorded in the user's history before returning so subsequent
// calls see the cumulative pattern. Detect never errors today, but the signature
// returns one to keep the API forward-compatible.
func (d *InferenceDetector) Detect(_ context.Context, user *model.UserContext, query QueryParams) (model.InferenceRisk, error) {
	if user == nil {
		return model.InferenceRisk{}, fmt.Errorf("inference detector: nil user")
	}

	hist := d.userHistory(user.UserID)
	hist.mu.Lock()
	hist.prune()
	previous := append([]QueryRecord(nil), hist.records...)
	hist.mu.Unlock()

	specificity := computeSpecificity(query)
	resultRisk := computeResultRisk(query.ExpectedResultCount)
	frequencyRisk := computeFrequencyRisk(previous)
	anomalyRisk := computeAnomalyRisk(previous, query.Category)

	// Equal weighting (0.25 each) — matches NIST SP 800-188 §3.2.3 recommendations.
	score := 0.25*specificity + 0.25*resultRisk + 0.25*frequencyRisk + 0.25*anomalyRisk
	if score > 1.0 {
		score = 1.0
	}

	factors := make([]string, 0, 4)
	if specificity >= 0.5 {
		factors = append(factors, fmt.Sprintf("high query specificity (%d filters)", len(query.Filters)))
	}
	if resultRisk >= 0.5 {
		factors = append(factors, fmt.Sprintf("small result set (%d)", query.ExpectedResultCount))
	}
	if frequencyRisk >= 0.5 {
		factors = append(factors, fmt.Sprintf("elevated query frequency (%d in last hour)", len(previous)))
	}
	if anomalyRisk >= 0.5 {
		factors = append(factors, "pattern anomaly: new category access")
	}

	action := classifyRisk(score)

	// Record the query AFTER computing the score so we never double-count it.
	rec := QueryRecord{
		Timestamp:   time.Now(),
		Category:    query.Category,
		FieldCount:  len(query.Filters),
		ResultCount: query.ExpectedResultCount,
		Specificity: specificity,
	}
	hist.mu.Lock()
	hist.records = append(hist.records, rec)
	if len(hist.records) > inferenceMaxHistory {
		hist.records = hist.records[len(hist.records)-inferenceMaxHistory:]
	}
	hist.mu.Unlock()

	return model.InferenceRisk{
		Score:   score,
		Action:  action,
		Factors: factors,
	}, nil
}

// userHistory returns (and creates if necessary) the history for userID.
func (d *InferenceDetector) userHistory(userID string) *userHistory {
	if v, ok := d.history.Load(userID); ok {
		return v.(*userHistory)
	}
	h := &userHistory{}
	actual, _ := d.history.LoadOrStore(userID, h)
	return actual.(*userHistory)
}

// prune drops records outside the inference window. Caller must hold mu.
func (h *userHistory) prune() {
	cutoff := time.Now().Add(-inferenceWindow)
	i := 0
	for ; i < len(h.records); i++ {
		if h.records[i].Timestamp.After(cutoff) {
			break
		}
	}
	if i > 0 {
		h.records = append([]QueryRecord(nil), h.records[i:]...)
	}
}

// computeSpecificity scales the number of filter fields onto [0,1].
// >5 filters → 1.0, 0 filters → 0.0.
func computeSpecificity(q QueryParams) float64 {
	n := len(q.Filters)
	if n <= 0 {
		return 0.0
	}
	if n >= 5 {
		return 1.0
	}
	return float64(n) / 5.0
}

// computeResultRisk: smaller result sets carry more re-identification risk.
// <5 results → 1.0, ≥50 results → 0.0, linear between.
func computeResultRisk(results int) float64 {
	if results <= 0 {
		// Unknown result count — treat as moderately risky rather than zero.
		return 0.5
	}
	if results < 5 {
		return 1.0
	}
	if results >= 50 {
		return 0.0
	}
	return 1.0 - float64(results-5)/45.0
}

// computeFrequencyRisk: >10 queries in the window → 1.0.
func computeFrequencyRisk(prev []QueryRecord) float64 {
	n := len(prev)
	if n <= 1 {
		return 0.0
	}
	if n >= 10 {
		return 1.0
	}
	return float64(n) / 10.0
}

// computeAnomalyRisk: high score when the user touches a category not seen before.
func computeAnomalyRisk(prev []QueryRecord, current model.DataCategory) float64 {
	if len(prev) == 0 {
		return 0.0
	}
	for _, r := range prev {
		if r.Category == current {
			return 0.0
		}
	}
	return 1.0
}

// classifyRisk maps a numeric score to the action recommendation.
func classifyRisk(score float64) string {
	switch {
	case score >= inferenceBlockThreshold:
		return "block"
	case score >= inferenceGeneralizeThreshold:
		return "generalize"
	case score >= inferenceWarnThreshold:
		return "warn"
	default:
		return "allow"
	}
}
