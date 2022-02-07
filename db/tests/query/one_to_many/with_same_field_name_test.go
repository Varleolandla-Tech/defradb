// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package one_to_many

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/db/tests"
)

var sameFieldNameGQLSchema = (`
	type book {
		name: String
		relationship1: author
	}

	type author {
		name: String
		relationship1: [book]
	}
`)

func executeSameFieldNameTestCase(t *testing.T, test testUtils.QueryTestCase) {
	testUtils.ExecuteQueryTestCase(t, sameFieldNameGQLSchema, []string{"book", "author"}, test)
}

func TestQueryOneToManyWithSameFieldName(t *testing.T) {
	tests := []testUtils.QueryTestCase{
		{
			Description: "One-to-many relation query from one side, same field name",
			Query: `query {
						book {
							name
							relationship1 {
								name
							}
						}
					}`,
			Docs: map[int][]string{
				//books
				0: { // bae-9217906d-e8c5-533d-8520-71c754590844
					(`{
					"name": "Painted House",
					"relationship1_id": "bae-2edb7fdd-cad7-5ad4-9c7d-6920245a96ed"
				}`)},
				//authors
				1: { // bae-2edb7fdd-cad7-5ad4-9c7d-6920245a96ed
					(`{
					"name": "John Grisham"
				}`)},
			},
			Results: []map[string]interface{}{
				{
					"name": "Painted House",
					"relationship1": map[string]interface{}{
						"name": "John Grisham",
					},
				},
			},
		},
		{
			Description: "One-to-many relation query from many side, same field name",
			Query: `query {
						author {
							name
							relationship1 {
								name
							}
						}
					}`,
			Docs: map[int][]string{
				//books
				0: { // bae-9217906d-e8c5-533d-8520-71c754590844
					(`{
					"name": "Painted House",
					"relationship1_id": "bae-2edb7fdd-cad7-5ad4-9c7d-6920245a96ed"
				}`)},
				//authors
				1: { // bae-2edb7fdd-cad7-5ad4-9c7d-6920245a96ed
					(`{
					"name": "John Grisham"
				}`)},
			},
			Results: []map[string]interface{}{
				{
					"name": "John Grisham",
					"relationship1": []map[string]interface{}{
						{
							"name": "Painted House",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		executeSameFieldNameTestCase(t, test)
	}
}
