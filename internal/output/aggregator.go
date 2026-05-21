package output

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/zafrem/bastion-vault/internal/model"
)

// Aggregator collapses a record set into a single synthetic record carrying only
// statistics — counts, numeric min/max/mean, and top-5 frequency distributions.
// Individual record contents are deliberately discarded; the only surviving
// per-input information is the field set itself.
type Aggregator struct{}

// NewAggregator constructs an Aggregator.
func NewAggregator() *Aggregator { return &Aggregator{} }

// Aggregate produces one synthetic DataRecord summarising the input set. The
// resulting record carries a special record_id ("aggregate") and a "count" field.
// Numeric fields gain "<field>_min", "<field>_max" and "<field>_mean" entries;
// string fields gain "<field>_top" carrying a top-5 frequency list.
//
// An empty input set returns a record with count=0 and no per-field statistics.
func (a *Aggregator) Aggregate(_ context.Context, records []model.DataRecord, category model.DataCategory) (model.DataRecord, error) {
	out := model.DataRecord{
		RecordID: "aggregate",
		Category: category,
		Fields: map[string]model.FieldValue{
			"count": {Value: len(records), Type: "aggregated"},
		},
	}

	if len(records) == 0 {
		return out, nil
	}

	// Inherit tenant from the first record so cross-tenant logic downstream still
	// sees a well-formed record.
	out.TenantID = records[0].TenantID

	// Collect per-field values across all records.
	numeric := make(map[string][]float64)
	categorical := make(map[string]map[string]int)

	for _, rec := range records {
		for name, fv := range rec.Fields {
			if n, ok := toFloat(fv.Value); ok {
				numeric[name] = append(numeric[name], n)
				continue
			}
			s := fmt.Sprintf("%v", fv.Value)
			if categorical[name] == nil {
				categorical[name] = make(map[string]int)
			}
			categorical[name][s]++
		}
	}

	// Emit numeric statistics.
	for name, values := range numeric {
		if len(values) == 0 {
			continue
		}
		min, max, sum := values[0], values[0], 0.0
		for _, v := range values {
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
			sum += v
		}
		mean := sum / float64(len(values))
		out.Fields[name+"_min"] = model.FieldValue{Value: min, Type: "aggregated"}
		out.Fields[name+"_max"] = model.FieldValue{Value: max, Type: "aggregated"}
		out.Fields[name+"_mean"] = model.FieldValue{Value: mean, Type: "aggregated"}
	}

	// Emit categorical top-5 distributions.
	for name, freq := range categorical {
		type kv struct {
			key   string
			count int
		}
		entries := make([]kv, 0, len(freq))
		for k, c := range freq {
			entries = append(entries, kv{k, c})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].count != entries[j].count {
				return entries[i].count > entries[j].count
			}
			return entries[i].key < entries[j].key
		})
		if len(entries) > 5 {
			entries = entries[:5]
		}
		top := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			top = append(top, map[string]any{"value": e.key, "count": e.count})
		}
		out.Fields[name+"_top"] = model.FieldValue{Value: top, Type: "aggregated"}
	}

	return out, nil
}

// toFloat coerces a Go value into a float64 when it represents a number.
// Strings parseable as numbers are accepted to handle JSON ints arriving as strings.
func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err == nil {
			return f, true
		}
	}
	return 0, false
}
