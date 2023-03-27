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

func TestQueryCommitsWithCollectionIDGroupedAndOrderedDesc(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple commits query with collectionId property grouped and ordered desc",
		Actions: []any{
			updateUserCollectionSchema(),
			updateCompaniesCollectionSchema(),
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
						"Name":	"John",
						"Age":	21
					}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
						"Name":	"Source"
					}`,
			},
			testUtils.Request{
				Request: ` {
					commits(groupBy: [collectionId], order: {collectionId: DESC}) {
						collectionId
					}
				}`,
				Results: []map[string]any{
					{
						"collectionId": int64(2),
					},
					{
						"collectionId": int64(1),
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users", "companies"}, test)
}

func TestQueryCommitsWithCollectionIDGroupedAndOrderedAs(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Simple commits query with collectionId property grouped and ordered asc",
		Actions: []any{
			updateUserCollectionSchema(),
			updateCompaniesCollectionSchema(),
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
						"Name":	"John",
						"Age":	21
					}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
						"Name":	"Source"
					}`,
			},
			testUtils.Request{
				Request: ` {
					commits(groupBy: [collectionId], order: {collectionId: ASC}) {
						collectionId
					}
				}`,
				Results: []map[string]any{
					{
						"collectionId": int64(1),
					},
					{
						"collectionId": int64(2),
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users", "companies"}, test)
}
