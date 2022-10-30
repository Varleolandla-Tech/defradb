package connor

import (
	"reflect"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/connor/numbers"
	"github.com/sourcenetwork/defradb/core"

	gql "github.com/graphql-go/graphql"
)

// eq is an operator which performs object equality
// tests.
func eq(condition, data any) (bool, error) {
	switch arr := data.(type) {
	case []core.Doc:
		for _, item := range arr {
			m, err := eq(condition, item)
			if err != nil {
				return false, err
			}

			if m {
				return true, nil
			}
		}
		return false, nil

	case client.Option[bool]:
		if !arr.HasValue() {
			return condition == nil, nil
		}
		data = arr.Value()

	case client.Option[int64]:
		if !arr.HasValue() {
			return condition == nil, nil
		}
		data = arr.Value()

	case client.Option[float64]:
		if !arr.HasValue() {
			return condition == nil, nil
		}
		data = arr.Value()

	case client.Option[string]:
		if !arr.HasValue() {
			return condition == nil, nil
		}
		data = arr.Value()
	}

	switch cn := condition.(type) {
	case string:
		if d, ok := data.(string); ok {
			return d == cn, nil
		}
		return false, nil
	case int64:
		return numbers.Equal(cn, data), nil
	case int:
		return numbers.Equal(cn, data), nil
	case float64:
		return numbers.Equal(cn, data), nil
	case map[FilterKey]any:
		m := true
		for prop, cond := range cn {
			var err error
			m, err = matchWith(prop.GetOperatorOrDefault("_eq"), cond, prop.GetProp(data))
			if err != nil {
				return false, err
			}

			if !m {
				// No need to evaluate after we fail
				break
			}
		}

		return m, nil
	// @todo: Are we OK with this spilling of GQL null types
	// into the connor eval package?
	case gql.NullValue:
		return data == nil, nil
	default:
		return reflect.DeepEqual(condition, data), nil
	}
}
