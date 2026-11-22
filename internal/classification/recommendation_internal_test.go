package classification

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zafrem/bastion-vault/internal/model"
)

// The recommendation states the k-anonymity threshold for the category; it must print the real number
// (including multi-digit ones), not a mangled digit.
func TestBuildRecommendation_PrintsTheThreshold(t *testing.T) {
	c := &Classifier{}
	l1 := []model.PIIDetection{{Sensitivity: model.SensitivityL1DirectIdentifier}}
	for cat, k := range defaultKThresholds {
		for _, det := range [][]model.PIIDetection{l1, nil} {
			got := c.buildRecommendation(cat, det)
			if want := fmt.Sprintf("K=%d", k); !strings.HasSuffix(got, want) {
				t.Errorf("%v: %q should end with %q", cat, got, want)
			}
		}
	}
	if len(defaultKThresholds) == 0 {
		t.Fatal("no thresholds to check")
	}
}
