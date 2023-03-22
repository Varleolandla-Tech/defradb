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

func TestQueryCommitsWithDockeyAndCidForDifferentDoc(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple all commits query with dockey and cid",
		Actions: []any{
			updateUserCollectionSchema(),
			createJohnDoc(),
			testUtils.Request{
				Request: ` {
						commits(
							dockey: "bae-not-this-doc",
							cid: "bafybeica4js2abwqjjrz7dcialbortbz32uxp7ufxu7yljbwvmhjqqxzny"
						) {
							cid
						}
					}`,
				Results: []map[string]any{},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users"}, test)
}

func TestQueryCommitsWithDockeyAndCidForDifferentDocWithUpdate(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple all commits query with dockey and cid",
		Actions: []any{
			updateUserCollectionSchema(),
			createJohnDoc(),
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc: `{
						"Age": 22
					}`,
			},
			testUtils.Request{
				Request: ` {
						commits(
							dockey: "bae-not-this-doc",
							cid: "bafybeica4js2abwqjjrz7dcialbortbz32uxp7ufxu7yljbwvmhjqqxzny"
						) {
							cid
						}
					}`,
				Results: []map[string]any{},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users"}, test)
}

func TestQueryCommitsWithDockeyAndCid(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple all commits query with dockey and cid",
		Actions: []any{
			updateUserCollectionSchema(),
			createJohnDoc(),
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc: `{
						"Age": 22
					}`,
			},
			testUtils.Request{
				Request: ` {
						commits(
							dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f",
							cid: "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m"
						) {
							cid
						}
					}`,
				Results: []map[string]any{
					{
						"cid": "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users"}, test)
}
