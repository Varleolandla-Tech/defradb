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

func TestDefaultExplainRequestWithFilterOnGroupByParent(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with filter on parent groupBy.",

		Request: `query @explain {
			Author (
				groupBy: [age],
				filter: {age: {_gt: 63}}
			) {
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
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be leaf of it's branch, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"age": dataMap{
							"_gt": int32(63),
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
		},
	}

	explainUtils.RunExplainTest(t, test)
}
