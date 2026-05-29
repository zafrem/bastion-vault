package classification_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/model"
)

// patternEngineRegexRoot returns the absolute path to the pii-pattern-engine
// regex directory, resolved relative to this source file.
func patternEngineRegexRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// vault/internal/classification/ → up 3 levels → bastion-rag/
	root := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	return filepath.Join(root, "sentinel", "external", "pii-pattern-engine", "regex")
}

func TestLoadPatternsFromDir_LoadsKoreanRRN(t *testing.T) {
	patterns := classification.LoadPatternsFromDir(patternEngineRegexRoot())
	reList, ok := patterns[model.PIIKoreanRRN]
	if !ok || len(reList) == 0 {
		t.Fatal("expected at least one compiled pattern for PIIKoreanRRN")
	}
	valid := "850315-1234568"
	matched := false
	for _, re := range reList {
		if re.MatchString(valid) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("none of the loaded RRN patterns matched %q", valid)
	}
}

func TestLoadPatternsFromDir_LoadsKoreanMobile(t *testing.T) {
	patterns := classification.LoadPatternsFromDir(patternEngineRegexRoot())
	reList, ok := patterns[model.PIIKoreanMobile]
	if !ok || len(reList) == 0 {
		t.Fatal("expected at least one compiled pattern for PIIKoreanMobile")
	}
	valid := "010-1234-5678"
	matched := false
	for _, re := range reList {
		if re.MatchString(valid) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("none of the loaded mobile patterns matched %q", valid)
	}
}

func TestLoadPatternsFromDir_RejectsInvalidRRNGenderCode(t *testing.T) {
	patterns := classification.LoadPatternsFromDir(patternEngineRegexRoot())
	reList := patterns[model.PIIKoreanRRN]
	// Gender/century code 9 is outside [1-4] (RRN) and [5-8] (alien) ranges.
	invalid := "850315-9234568"
	for _, re := range reList {
		if re.MatchString(invalid) {
			t.Errorf("RRN pattern should not match gender code 9 in %q", invalid)
		}
	}
}

func TestLoadPatternsFromDir_NonexistentDirReturnsEmpty(t *testing.T) {
	patterns := classification.LoadPatternsFromDir("/nonexistent/path")
	if len(patterns) != 0 {
		t.Errorf("expected empty map for nonexistent dir, got %d entries", len(patterns))
	}
}

func TestLoadPatternsFromDir_BadYAMLIsSkipped(t *testing.T) {
	dir := t.TempDir()
	krDir := filepath.Join(dir, "pii", "kr")
	if err := os.MkdirAll(krDir, 0755); err != nil {
		t.Fatal(err)
	}
	badYAML := filepath.Join(krDir, "bad.yml")
	if err := os.WriteFile(badYAML, []byte("patterns: [\nunclosed"), 0600); err != nil {
		t.Fatal(err)
	}
	// Must not panic; returns empty map.
	patterns := classification.LoadPatternsFromDir(dir)
	if len(patterns) != 0 {
		t.Errorf("expected empty map for bad YAML, got %d entries", len(patterns))
	}
}
