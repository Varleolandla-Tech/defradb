package filter

import (
	"github.com/sourcenetwork/defradb/connor"
	"github.com/sourcenetwork/defradb/planner/mapper"
)

func conditionsArrToMap(conditions []any) map[connor.FilterKey]any {
	result := make(map[connor.FilterKey]any)
	for _, clause := range conditions {
		if clauseMap, ok := clause.(map[connor.FilterKey]any); ok {
			for k, v := range clauseMap {
				result[k] = v
			}
		}
	}
	return result
}

func addNormalizedCondition(key connor.FilterKey, val any, m map[connor.FilterKey]any) {
	if _, isProp := key.(*mapper.PropertyIndex); isProp {
		var andOp *mapper.Operator
		var andContent []any
		for existingKey := range m {
			if op, isOp := existingKey.(*mapper.Operator); isOp && op.Operation == "_and" {
				andOp = op
				andContent = m[existingKey].([]any)
				break
			}
		}
		for existingKey := range m {
			if existingKey.Equal(key) {
				existingVal := m[existingKey]
				delete(m, existingKey)
				if andOp == nil {
					andOp = &mapper.Operator{Operation: "_and"}
				}
				m[andOp] = append(
					andContent,
					map[connor.FilterKey]any{existingKey: existingVal},
					map[connor.FilterKey]any{key: val},
				)
				return
			}
		}
		for _, andElement := range andContent {
			elementMap := andElement.(map[connor.FilterKey]any)
			for andElementKey := range elementMap {
				if andElementKey.Equal(key) {
					m[andOp] = append(andContent, map[connor.FilterKey]any{key: val})
					return
				}
			}
		}
	}
	m[key] = val
}

func normalizeConditions(conditions any, skipRoot bool) any {
	result := make(map[connor.FilterKey]any)
	switch typedConditions := conditions.(type) {
	case map[connor.FilterKey]any:
		for rootKey, rootVal := range typedConditions {
			rootOpKey, isRootOp := rootKey.(*mapper.Operator)
			if isRootOp {
				if rootOpKey.Operation == "_and" || rootOpKey.Operation == "_or" {
					rootValArr := rootVal.([]any)
					if len(rootValArr) == 1 || rootOpKey.Operation == "_and" && !skipRoot {
						flat := normalizeConditions(conditionsArrToMap(rootValArr), false)
						flatMap := flat.(map[connor.FilterKey]any)
						for k, v := range flatMap {
							addNormalizedCondition(k, v, result)
						}
					} else {
						resultArr := []any{}
						for i := range rootValArr {
							norm := normalizeConditions(rootValArr[i], !skipRoot)
							normMap, ok := norm.(map[connor.FilterKey]any)
							if ok {
								for k, v := range normMap {
									resultArr = append(resultArr, map[connor.FilterKey]any{k: v})
								}
							} else {
								resultArr = append(resultArr, norm)
							}
						}
						addNormalizedCondition(rootKey, resultArr, result)
					}
				} else if rootOpKey.Operation == "_not" {
					notMap := rootVal.(map[connor.FilterKey]any)
					if len(notMap) == 1 {
						var k connor.FilterKey
						for k = range notMap {
							break
						}
						norm := normalizeConditions(notMap, true).(map[connor.FilterKey]any)
						delete(notMap, k)
						var v any
						for k, v = range norm {
							break
						}
						if opKey, ok := k.(*mapper.Operator); ok && opKey.Operation == "_not" {
							notNotMap := normalizeConditions(v, false).(map[connor.FilterKey]any)
							for notNotKey, notNotVal := range notNotMap {
								addNormalizedCondition(notNotKey, notNotVal, result)
							}
						} else {
							notMap[k] = v
							addNormalizedCondition(rootOpKey, notMap, result)
						}
					} else {
						addNormalizedCondition(rootKey, rootVal, result)
					}
				} else {
					addNormalizedCondition(rootKey, rootVal, result)
				}
			} else {
				addNormalizedCondition(rootKey, normalizeConditions(rootVal, false), result)
			}
		}
		return result
	case []any:
		return conditionsArrToMap(typedConditions)
	default:
		return conditions
	}
}

func Normalize(conditions map[connor.FilterKey]any) map[connor.FilterKey]any {
	return normalizeConditions(conditions, false).(map[connor.FilterKey]any)
}
