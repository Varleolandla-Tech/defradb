// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain_default

import (
	"testing"

	explainUtils "github.com/sourcenetwork/defradb/tests/integration/explain"
)

var groupPattern = dataMap{
	"explain": dataMap{
		"selectTopNode": dataMap{
			"groupNode": dataMap{
				"selectNode": dataMap{
					"scanNode": dataMap{},
				},
			},
		},
	},
}

func TestDefaultExplainRequestWithGroupByOnParent(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with group-by on parent.",

		Request: `query @explain {
			Author (groupBy: [age]) {
				age
				_group {
					name
				}
			}
		}`,

		Docs: map[int][]string{
			//authors
			2: {
				`{
					"name": "John Grisham",
					"age": 65
				}`,

				`{
					"name": "Cornelia Funke",
					"age": 62
				}`,

				`{
					"name": "John's Twin",
					"age": 65
				}`,
			},
		},

		ExpectedPatterns: []dataMap{groupPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "groupNode",
				IncludeChildNodes: false,
				ExpectedAttributes: dataMap{
					"groupByFields": []string{"age"},
					"childSelects": []dataMap{
						emptyChildSelectsAttributeForAuthor,
					},
				},
			},
		},
	}

	explainUtils.RunExplainTest(t, test)
}

func TestDefaultExplainRequestWithGroupByTwoFieldsOnParent(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with group-by two fields on parent.",

		Request: `query @explain {
			Author (groupBy: [age, name]) {
				age
				_group {
					name
				}
			}
		}`,

		Docs: map[int][]string{
			//authors
			2: {
				`{
					"name": "John Grisham",
					"age": 65
				}`,

				`{
					"name": "Cornelia Funke",
					"age": 62
				}`,

				`{
					"name": "John's Twin",
					"age": 65
				}`,
			},
		},

		ExpectedPatterns: []dataMap{groupPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "groupNode",
				IncludeChildNodes: false,
				ExpectedAttributes: dataMap{
					"groupByFields": []string{"age", "name"},
					"childSelects": []dataMap{
						emptyChildSelectsAttributeForAuthor,
					},
				},
			},
		},
	}

	explainUtils.RunExplainTest(t, test)
}
