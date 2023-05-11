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

var averagePattern = dataMap{
	"explain": dataMap{
		"selectTopNode": dataMap{
			"averageNode": dataMap{
				"countNode": dataMap{
					"sumNode": dataMap{
						"selectNode": dataMap{
							"scanNode": dataMap{},
						},
					},
				},
			},
		},
	},
}

func TestDefaultExplainRequestWithAverageOnArrayField(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with average on array field.",

		Request: `query @explain {
			Book {
				name
				_avg(chapterPages: {})
			}
		}`,

		Docs: map[int][]string{
			// books
			1: {
				`{
					"name": "Painted House",
					"chapterPages": [1, 22, 33, 44, 55, 66]
				}`,
				`{
					"name": "A Time for Mercy",
					"chapterPages": [0, 22, 101, 321]
				}`,
			},
		},

		ExpectedPatterns: []dataMap{averagePattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:     "averageNode",
				IncludeChildNodes:  false,
				ExpectedAttributes: dataMap{}, // no attributes
			},
			{
				TargetNodeName:    "countNode",
				IncludeChildNodes: false,
				ExpectedAttributes: dataMap{
					"sources": []dataMap{
						{
							"filter":    dataMap{"_ne": nil},
							"fieldName": "chapterPages",
						},
					},
				},
			},
			{
				TargetNodeName:    "sumNode",
				IncludeChildNodes: false,
				ExpectedAttributes: dataMap{
					"sources": []dataMap{
						{
							"filter":         dataMap{"_ne": nil},
							"fieldName":      "chapterPages",
							"childFieldName": nil,
						},
					},
				},
			},
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "2",
					"collectionName": "Book",
					"filter":         nil,
					"spans": []dataMap{
						{
							"start": "/2",
							"end":   "/3",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}
