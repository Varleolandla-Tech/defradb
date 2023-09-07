package filter

import (
	"github.com/sourcenetwork/defradb/connor"
	"github.com/sourcenetwork/defradb/planner/mapper"
)

// Merge merges two filters into one.
// It basically applies _and to both filters and normalizes them.
func Merge(dest map[connor.FilterKey]any, src map[connor.FilterKey]any) map[connor.FilterKey]any {
	if dest == nil {
		dest = make(map[connor.FilterKey]any)
	}

	result := map[connor.FilterKey]any{
		&mapper.Operator{Operation: "_and"}: []any{
			dest, src,
		},
	}

	return Normalize(result)
}
