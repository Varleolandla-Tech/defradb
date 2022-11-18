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

func TestQuerySimpleWithDateTimeEqualsFilterBlock(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with basic filter(age)",
		Query: `query {
					users(filter: {CreatedAt: {_eq: "2017-07-23T03:46:56.647Z"}}) {
						Name
						Age
						CreatedAt
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21,
					"CreatedAt": "2017-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Bob",
					"Age": 32,
					"CreatedAt": "2016-07-23T03:46:56.647Z"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name":      "John",
				"Age":       uint64(21),
				"CreatedAt": "2017-07-23T03:46:56.647Z",
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithDateTimeEqualsNilFilterBlock(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with basic filter(age)",
		Query: `query {
					users(filter: {CreatedAt: {_eq: null}}) {
						Name
						Age
						CreatedAt
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21,
					"CreatedAt": "2017-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Bob",
					"Age": 32,
					"CreatedAt": "2016-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Fred",
					"Age": 44
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name":      "Fred",
				"Age":       uint64(44),
				"CreatedAt": nil,
			},
		},
	}

	executeTestCase(t, test)
}
