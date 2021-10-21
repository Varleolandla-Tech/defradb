// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package simple

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/db/tests"
)

func TestQuerySimple(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with no filter",
		Query: `query {
					users {
						_key
						Name
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"Age": 21
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"_key": "bae-52b9170d-b77a-5887-b877-cbdbb99b009f",
				"Name": "John",
				"Age":  uint64(21),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithAlias(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with alias, no filter",
		Query: `query {
					users {
						username: Name
						age: Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"Age": 21
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"username": "John",
				"age":      uint64(21),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithMultipleRows(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with no filter, mutiple rows",
		Query: `query {
					users {
						Name
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"Age": 21
			}`),
				(`{
				"Name": "Bob",
				"Age": 27
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "Bob",
				"Age":  uint64(27),
			},
			{
				"Name": "John",
				"Age":  uint64(21),
			},
		},
	}

	executeTestCase(t, test)
}
