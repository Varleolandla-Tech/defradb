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

var topLevelSumPattern = dataMap{
	"explain": dataMap{
		"topLevelNode": []dataMap{
			{
				"selectTopNode": dataMap{
					"selectNode": dataMap{
						"scanNode": dataMap{},
					},
				},
			},
			{
				"sumNode": dataMap{},
			},
		},
	},
}

func TestDefaultExplainTopLevelSumRequest(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) top-level sum request.",

		Request: `query @explain {
			_sum(
				Author: {
					field: age
				}
			)
		}`,

		Docs: map[int][]string{
			//Authors
			2: {
				`{
					"name": "John",
					"verified": true,
					"age": 21
				}`,
				`{
					"name": "Bob",
					"verified": true,
					"age": 30
				}`,
			},
		},

		ExpectedPatterns: []dataMap{topLevelSumPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter":         nil,
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
			{
				TargetNodeName:    "sumNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"sources": []dataMap{
						{
							"fieldName":      "Author",
							"childFieldName": "age",
							"filter":         nil,
						},
					},
				},
			},
		},
	}

	explainUtils.RunExplainTest(t, test)
}

func TestDefaultExplainTopLevelSumRequestWithFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) top-level sum request with filter.",

		Request: `query @explain {
			_sum(
				Author: {
					field: age,
					filter: {
						age: {
							_gt: 26
						}
					}
				}
			)
		}`,

		Docs: map[int][]string{
			//Authors
			2: {
				`{
					"name": "John",
					"verified": false,
					"age": 21
				}`,
				`{
					"name": "Bob",
					"verified": false,
					"age": 30
				}`,
				`{
					"name": "Alice",
					"verified": true,
					"age": 32
				}`,
			},
		},

		ExpectedPatterns: []dataMap{topLevelSumPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"age": dataMap{
							"_gt": int32(26),
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
			{
				TargetNodeName:    "sumNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"sources": []dataMap{
						{
							"fieldName":      "Author",
							"childFieldName": "age",
							"filter": dataMap{
								"age": dataMap{
									"_gt": int32(26),
								},
							},
						},
					},
				},
			},
		},
	}

	explainUtils.RunExplainTest(t, test)
}
