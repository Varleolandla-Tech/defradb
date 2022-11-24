// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain

import (
	"context"
	"reflect"
	"testing"

	"github.com/sourcenetwork/immutable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/logging"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

var (
	log = logging.MustNewLogger("defra.tests.integration.explain")

	allPlanNodeNames = map[string]struct{}{
		// Not a planNode but need it here as this is root of the explain graph.
		"explain": {},

		// These are not planNodes but we need to include them here, because typeIndexJoin wraps some nodes
		// under `root` and `subType` attribute (without these they would be skipped from the ordering pattern).
		"root":    {},
		"subType": {},

		// These are all valid nodes.
		"averageNode":   {},
		"countNode":     {},
		"createNode":    {},
		"dagScanNode":   {},
		"deleteNode":    {},
		"groupNode":     {},
		"limitNode":     {},
		"multiScanNode": {},
		"orderNode":     {},
		"parallelNode":  {},
		"pipeNode":      {},
		"scanNode":      {},
		"selectNode":    {},
		"selectTopNode": {},
		"sumNode":       {},
		"topLevelNode":  {},
		"typeIndexJoin": {},
		"typeJoinMany":  {},
		"typeJoinOne":   {},
		"updateNode":    {},
		"valuesNode":    {},
	}
)

type PlanNodeTargetCase struct {
	// Name of the plan node, whose attribute(s) we are targetting to be asserted.
	TargetNodeName string

	// How many occurances of this target name to skip until target (0 means match first).
	OccurancesToSkip uint

	// If set to 'true' will include the nested node(s), with their attribute(s) as well.
	IncludeChildNodes bool

	// Expected value of the target node's attribute(s).
	ExpectedAttributes any
}

type ExplainRequestTestCase struct {
	Description string

	// Has to be a valid explain request type (one of: 'simple', 'debug', 'execute', 'predict').
	Request string

	// Docs is a map from Collection Index, to a list
	// of docs in stringified JSON format
	Docs map[int][]string

	// The raw expected explain graph with everything (helpful for debugging purposes).
	// Note: This is not always asserted (i.e. ignored from the comparison if not provided).
	ExpectedFullGraph []map[string]any

	// Pattern is used to assert that the plan nodes are in the correct order (attributes are omitted).
	// Note: - Explain requests of type 'debug' will only have Pattern (as they don't have attributes).
	//       - This is not always asserted (i.e. ignored from the comparison if not provided).
	ExpectedPatterns []map[string]any

	// Every target helps assert an individual node somewhere in the explain graph (node's position is omitted).
	// Each target assertion is only responsible to check if the node's attributes are correct.
	// Note: This is not always asserted (i.e. ignored from the comparison if not provided).
	ExpectedTargets []PlanNodeTargetCase

	// The expected error from the explain request.
	ExpectedError string
}

func ExecuteExplainRequestTestCase(
	t *testing.T,
	schema string,
	collectionNames []string,
	explainTest ExplainRequestTestCase,
) {
	if testUtils.DetectDbChanges && testUtils.DetectDbChangesPreTestChecks(t, collectionNames, false) {
		return
	}

	// Must have a non-empty request.
	if explainTest.Request == "" {
		assert.Fail(t, "Explain test must have a non-empty request.", explainTest.Description)
	}

	// If no expected results are provided, then it's invalid use of this explain testing setup.
	if explainTest.ExpectedFullGraph == nil &&
		explainTest.ExpectedPatterns == nil &&
		explainTest.ExpectedTargets == nil {
		assert.Fail(t, "Atleast one expected explain parameter must be provided.", explainTest.Description)
	}

	ctx := context.Background()
	dbs, err := testUtils.GetDatabases(ctx, t, false)
	if testUtils.AssertError(t, explainTest.Description, err, explainTest.ExpectedError) {
		return
	}
	require.NotEmpty(t, dbs)

	for _, dbi := range dbs {
		log.Info(ctx, explainTest.Description, logging.NewKV("Database", dbi.Name()))

		if testUtils.DetectDbChanges {
			if testUtils.SetupOnly {
				testUtils.SetupDatabase(
					ctx,
					t,
					dbi,
					schema,
					collectionNames,
					explainTest.Description,
					explainTest.ExpectedError,
					explainTest.Docs,
					immutable.None[map[int]map[int][]string](),
				)
				dbi.DB().Close(ctx)
				return
			}

			dbi = testUtils.SetupDatabaseUsingTargetBranch(ctx, t, dbi, collectionNames)
		} else {
			testUtils.SetupDatabase(
				ctx,
				t,
				dbi,
				schema,
				collectionNames,
				explainTest.Description,
				explainTest.ExpectedError,
				explainTest.Docs,
				immutable.None[map[int]map[int][]string](),
			)
		}

		result := dbi.DB().ExecQuery(ctx, explainTest.Request)
		if assertExplainRequestResults(
			ctx,
			t,
			&result.GQL,
			explainTest,
		) {
			continue
		}

		if explainTest.ExpectedError != "" {
			assert.Fail(t, "Expected an error however none was raised.", explainTest.Description)
		}

		dbi.DB().Close(ctx)
	}
}

func assertExplainRequestResults(
	ctx context.Context,
	t *testing.T,
	actualResult *client.GQLResult,
	explainTest ExplainRequestTestCase,
) bool {
	// Check expected error matches actual error.
	if testUtils.AssertErrors(
		t,
		explainTest.Description,
		actualResult.Errors,
		explainTest.ExpectedError,
	) {
		return true
	}

	// Note: if returned gql result is `nil` this panics (the panic seems useful while testing).
	resultantData := actualResult.Data.([]map[string]any)
	log.Info(ctx, "", logging.NewKV("FullExplainGraphResult", actualResult.Data))

	// Check if the expected full explain graph (if provided) matches the actual full explain graph
	// that is returned, if doesn't match we would like to still see a diff comparison (handy while debugging).
	if lengthOfExpectedFullGraph := len(explainTest.ExpectedFullGraph); explainTest.ExpectedFullGraph != nil {
		require.Equal(t, lengthOfExpectedFullGraph, len(resultantData), explainTest.Description)
		for index, actualResult := range resultantData {
			if lengthOfExpectedFullGraph > index {
				assert.Equal(
					t,
					explainTest.ExpectedFullGraph[index],
					actualResult,
					explainTest.Description,
				)
			}
		}
	}

	// Ensure the complete high-level pattern matches, inother words check that all the
	// explain graph nodes are in the correct expected ordering.
	if explainTest.ExpectedPatterns != nil {
		require.Equal(t, len(explainTest.ExpectedPatterns), len(resultantData), explainTest.Description)
		for index, actualResult := range resultantData {
			// Trim away all attributes (non-plan nodes) from the returned full explain graph result.
			actualResultWithoutAttributes := trimExplainAttributes(t, explainTest.Description, actualResult)
			assert.Equal(
				t,
				explainTest.ExpectedPatterns[index],
				actualResultWithoutAttributes,
				explainTest.Description,
			)
		}
	}

	// Match the targeted node's attributes (subset assertions), with the expected attributes.
	// Note: This does not check if the node is in correct location or not.
	if explainTest.ExpectedTargets != nil {
		for _, target := range explainTest.ExpectedTargets {
			assertExplainTargetCase(t, explainTest.Description, target, resultantData)
		}
	}

	return false
}

func assertExplainTargetCase(
	t *testing.T,
	description string,
	targetCase PlanNodeTargetCase,
	actualResults []map[string]any,
) {
	for _, actualResult := range actualResults {
		foundActualTarget, _, isFound := findTargetNode(
			targetCase.TargetNodeName,
			targetCase.OccurancesToSkip,
			targetCase.IncludeChildNodes,
			actualResult,
		)

		if !isFound {
			assert.Fail(
				t,
				"Expected target ["+targetCase.TargetNodeName+"], was not found in the explain graph.",
				description,
			)
		}

		assert.Equal(
			t,
			targetCase.ExpectedAttributes,
			foundActualTarget,
			description,
		)
	}
}

// findTargetNode returns true if the targetName is found in the explain graph after skipping given number of
// occurances, 0 means first occurance. The function also returns total occurances it encountered so far. The
// returned count of 'matches' should always be <= occurance argument.
func findTargetNode(
	targetName string,
	toSkip uint,
	includeChildNodes bool,
	actualResult any,
) (any, uint, bool) {
	var totalMatchedSoFar uint = 0

	switch r := actualResult.(type) {
	case map[string]any:
		for key, value := range r {
			if isPlanNode(key) {
				if key == targetName {
					totalMatchedSoFar++

					if toSkip == 0 {
						if includeChildNodes {
							return value, totalMatchedSoFar, true
						}
						return trimSubNodes(value), totalMatchedSoFar, true
					}

					toSkip--
					target, matches, found := findTargetNode(
						targetName,
						toSkip,
						includeChildNodes,
						value,
					)

					totalMatchedSoFar = totalMatchedSoFar + matches
					toSkip -= matches

					if found {
						if includeChildNodes {
							return target, totalMatchedSoFar, true
						}
						return trimSubNodes(target), totalMatchedSoFar, true
					}
				} else {
					// Not a match, traverse furthur.
					target, matches, found := findTargetNode(
						targetName,
						toSkip,
						includeChildNodes,
						value,
					)

					totalMatchedSoFar = totalMatchedSoFar + matches
					toSkip -= matches

					if found {
						if includeChildNodes {
							return target, totalMatchedSoFar, true
						}
						return trimSubNodes(target), totalMatchedSoFar, true
					}
				}
			}
		}

	case []map[string]any:
		for _, item := range r {
			target, matches, found := findTargetNode(
				targetName,
				toSkip,
				includeChildNodes,
				item,
			)

			totalMatchedSoFar = totalMatchedSoFar + matches
			toSkip -= matches

			if found {
				if includeChildNodes {
					return target, totalMatchedSoFar, true
				}
				return trimSubNodes(target), totalMatchedSoFar, true
			}
		}
	}

	return nil, totalMatchedSoFar, false
}

// trimSubNodes returns a graph where all the immediate sub nodes are trimmed (i.e. no nested subnodes remain).
func trimSubNodes(graph any) any {
	checkGraph, ok := graph.(map[string]any)
	if !ok {
		return graph
	}

	// Copying is super important here so we don't trim the actual result (as we might want to continue using it),
	trimGraph := copyMap(checkGraph)
	for key := range trimGraph {
		if isPlanNode(key) {
			delete(trimGraph, key)
		}
	}

	return trimGraph
}

// trimExplainAttributes trims away all keys that aren't plan nodes within the explain graph.
func trimExplainAttributes(
	t *testing.T,
	description string,
	actualResult map[string]any,
) map[string]any {
	trimmedMap := copyMap(actualResult)

	for key, value := range trimmedMap {
		if !isPlanNode(key) {
			delete(trimmedMap, key)
			continue
		}

		switch v := value.(type) {
		case map[string]any:
			trimmedMap[key] = trimExplainAttributes(t, description, v)

		case []map[string]any:
			trimmedArrayElements := []map[string]any{}
			for _, valueItem := range v {
				trimmedArrayElements = append(
					trimmedArrayElements,
					trimExplainAttributes(t, description, valueItem),
				)
			}
			trimmedMap[key] = trimmedArrayElements

		default:
			assert.Fail(
				t,
				"Unsupported explain graph key-value type encountered: "+reflect.TypeOf(v).String(),
				description,
			)
		}
	}

	return trimmedMap
}

// isPlanNode returns true if someName matches a plan node name, retruns false otherwise.
func isPlanNode(someName string) bool {
	_, isPlanNode := allPlanNodeNames[someName]
	return isPlanNode
}

func copyMap(originalMap map[string]any) map[string]any {
	newMap := make(map[string]any, len(originalMap))
	for oKey, oValue := range originalMap {
		switch v := oValue.(type) {
		case map[string]any:
			newMap[oKey] = copyMap(v)

		case []map[string]any:
			newList := make([]map[string]any, len(v))
			for index, item := range v {
				newList[index] = copyMap(item)
			}
			newMap[oKey] = newList

		default:
			newMap[oKey] = oValue
		}
	}
	return newMap
}
