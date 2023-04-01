// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain_execute

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestExecuteExplainRequestWithCountOnOneToManyRelation(t *testing.T) {
	test := testUtils.TestCase{

		Description: "Explain (execute) request with count on one to many relation.",

		Actions: []any{
			gqlSchemaExecuteExplain(),

			// Books
			create3BookDocuments(),

			// Authors
			create2AuthorDocuments(),

			testUtils.Request{
				Request: `query @explain(type: execute) {
					Author {
						name
						numberOfBooks: _count(books: {})
					}
				}`,

				Results: []dataMap{
					{
						"explain": dataMap{
							"executionSuccess": true,
							"sizeOfResult":     2,
							"planExecutions":   uint64(3),
							"selectTopNode": dataMap{
								"countNode": dataMap{
									"iterations": uint64(3),
									"selectNode": dataMap{
										"iterations":    uint64(3),
										"filterMatches": uint64(2),
										"typeIndexJoin": dataMap{
											"iterations": uint64(3),
											"scanNode": dataMap{
												"iterations":    uint64(3),
												"docFetches":    uint64(3),
												"filterMatches": uint64(2),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}
