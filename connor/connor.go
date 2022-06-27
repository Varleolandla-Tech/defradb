package connor

import (
	"fmt"
	"strings"

	"github.com/sourcenetwork/defradb/core"
)

// Match is the default method used in Connor to match some data to a
// set of conditions.
func Match(conditions map[FilterKey]interface{}, data core.Doc) (bool, error) {
	return MatchWith("$eq", conditions, data)
}

// MatchWith can be used to specify the exact operator to use when performing
// a match operation. This is primarily used when building custom operators or
// if you wish to override the behavior of another operator.
func MatchWith(op string, conditions, data interface{}) (bool, error) {
	if !strings.HasPrefix(op, "$") {
		return false, fmt.Errorf("operator should have '$' prefix")
	}

	o, ok := opMap[op[1:]]
	if !ok {
		return false, fmt.Errorf("unknown operator '%s'", op[1:])
	}

	return o.Evaluate(conditions, data)
}
