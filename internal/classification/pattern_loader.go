package classification

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/zafrem/bastion-vault/internal/model"
	"gopkg.in/yaml.v3"
)

// patternFile mirrors the top-level structure of pii-pattern-engine YAML files.
type patternFile struct {
	Patterns []yamlPattern `yaml:"patterns"`
}

type yamlPattern struct {
	ID    string            `yaml:"id"`
	Langs map[string]string `yaml:"langs"`
}

// patternIDtoPII maps pii-pattern-engine pattern IDs to Vault PIITypes.
// Only IDs whose Go pattern we want to use are listed here.
var patternIDtoPII = map[string]model.PIIType{
	"rrn_01":                model.PIIKoreanRRN,
	"alien_registration_01": model.PIIKoreanRRN,
	"mobile_01":             model.PIIKoreanMobile,
	"mobile_02":             model.PIIKoreanMobile,
}

// LoadPatternsFromDir reads YAML pattern files from regexRoot/pii/kr/ and returns
// compiled Go regexes keyed by PIIType. Unknown pattern IDs are silently skipped.
// Parse or compile errors are also silently skipped so a bad pattern never brings
// down the classifier; the hardcoded fallbacks remain active.
func LoadPatternsFromDir(regexRoot string) map[model.PIIType][]*regexp.Regexp {
	out := make(map[model.PIIType][]*regexp.Regexp)
	// Read through an os.Root so a symlink in the directory cannot lead the loader to a file outside it,
	// and the directory cannot be swapped between listing and reading (CWE-22/367).
	root, err := os.OpenRoot(filepath.Join(regexRoot, "pii", "kr"))
	if err != nil {
		return out // no pattern directory: the hardcoded fallbacks stay in use
	}
	defer root.Close()
	files, _ := fs.Glob(root.FS(), "*.yml")
	for _, f := range files {
		data, err := root.ReadFile(f)
		if err != nil {
			continue
		}
		var pf patternFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			continue
		}
		for _, p := range pf.Patterns {
			pt, ok := patternIDtoPII[p.ID]
			if !ok {
				continue
			}
			goPattern, ok := p.Langs["go"]
			if !ok || goPattern == "" {
				continue
			}
			re, err := regexp.Compile(goPattern)
			if err != nil {
				continue
			}
			out[pt] = append(out[pt], re)
		}
	}
	return out
}

// matchesLoaded returns true if value matches any loaded pattern for pt.
func matchesLoaded(pt model.PIIType, value string) bool {
	for _, re := range _loadedPatterns[pt] {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
