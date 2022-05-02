// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package inline_array

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/db/tests"
)

// Note: this test should follow a different code path to `_avg` on it's own
// utilising the existing `_sum` node instead of adding a new one.  This test cannot
// verify that that code path is taken, but it does verfiy that the correct result
// is returned to the consumer in case the more efficient code path is taken.
func TestQueryInlineIntegerArrayWithAverageAndSum(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, average and sum of populated integer array",
		Query: `query {
					users(groupBy: [Name]) {
						Name
						_avg(FavouriteIntegers: {})
						_sum(FavouriteIntegers: {})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteIntegers": [-1, 0, 9, 0]
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_avg": float64(2),
				"_sum": int64(8),
			},
		},
	}

	executeTestCase(t, test)
}
