// Copyright 2022 Democratized Data Foundation
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

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQuerySimpleWithIntInFilter(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with special filter (or)",
		Query: `query {
					users(filter: {Age: {_in: [19, 40, 55]}}) {
						Name
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
				`{
					"Name": "Bob",
					"Age": 32
				}`,
				`{
					"Name": "Carlo",
					"Age": 55
				}`,
				`{
					"Name": "Alice",
					"Age": 19
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name": "Alice",
				"Age":  uint64(19),
			},
			{
				"Name": "Carlo",
				"Age":  uint64(55),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithIntInFilterWithNullValue(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with special filter (or)",
		Query: `query {
					users(filter: {Age: {_in: [19, 40, 55, null]}}) {
						Name
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
				`{
					"Name": "Bob",
					"Age": 32
				}`,
				`{
					"Name": "Carlo",
					"Age": 55
				}`,
				`{
					"Name": "Alice",
					"Age": 19
				}`,
				`{
					"Name": "Fred"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name": "Fred",
				"Age":  nil,
			},
			{
				"Name": "Alice",
				"Age":  uint64(19),
			},
			{
				"Name": "Carlo",
				"Age":  uint64(55),
			},
		},
	}

	executeTestCase(t, test)
}
