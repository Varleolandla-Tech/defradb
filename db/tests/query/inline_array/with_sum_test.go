// Copyright 2020 Source Inc.
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

func TestQueryInlineIntegerArrayWithsWithSumAndNullArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of nil integer array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteIntegers: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteIntegers": null
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_sum": int64(0),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryInlineIntegerArrayWithsWithSumAndEmptyArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of empty integer array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteIntegers: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteIntegers": []
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_sum": int64(0),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryInlineIntegerArrayWithsWithSumAndPopulatedArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of integer array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteIntegers: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "Shahzad",
				"FavouriteIntegers": [-1, 2, -1, 1, 0]
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "Shahzad",
				"_sum": int64(1),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryInlineFloatArrayWithsWithSumAndNullArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of nil float array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteFloats: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteFloats": null
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_sum": float64(0),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryInlineFloatArrayWithsWithSumAndEmptyArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of empty float array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteFloats: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteFloats": []
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_sum": float64(0),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryInlineFloatArrayWithsWithSumAndPopulatedArray(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple inline array with no filter, sum of float array",
		Query: `query {
					users {
						Name
						_sum(field: {FavouriteFloats: {}})
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"FavouriteFloats": [3.1425, 0.00000000001, 10]
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"_sum": float64(13.14250000001),
			},
		},
	}

	executeTestCase(t, test)
}
