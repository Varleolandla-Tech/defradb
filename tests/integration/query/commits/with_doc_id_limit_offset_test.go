// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package commits

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryCommitsWithDocIDAndLimitAndOffset(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple all commits query with docID, limit and offset",
		Actions: []any{
			updateUserCollectionSchema(),
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
						"name":	"John",
						"age":	21
					}`,
			},
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc: `{
					"age":	22
				}`,
			},
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc: `{
					"age":	23
				}`,
			},
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc: `{
					"age":	24
				}`,
			},
			testUtils.Request{
				Request: ` {
						commits(docID: "bae-c9fb0fa4-1195-589c-aa54-e68333fb90b3", limit: 2, offset: 1) {
							cid
						}
					}`,
				Results: []map[string]any{
					{
						"cid": "bafyreicoci4ah2uft5giiyl2lfg4jgcegwbvt3mbllnqnmfh3oy24usxsy",
					},
					{
						"cid": "bafyreigurfgpfvcm4uzqxjf4ur3xegxbebn6yoogjrvyaw6x7d2ji6igim",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
