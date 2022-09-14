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

func TestQuerySimpleWithFloatNotEqualsFilterBlock(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with ne float filter",
		Query: `query {
					users(filter: {HeightM: {_ne: 2.1}}) {
						Name
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"HeightM": 2.1
				}`,
				`{
					"Name": "Bob",
					"HeightM": 3.2
				}`,
			},
		},
		Results: []map[string]interface{}{
			{
				"Name": "Bob",
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithFloatNotEqualsNilFilterBlock(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with ne float nil filter",
		Query: `query {
					users(filter: {HeightM: {_ne: null}}) {
						Name
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"HeightM": 2.1
				}`,
				`{
					"Name": "Bob",
					"HeightM": 3.2
				}`,
				`{
					"Name": "Fred"
				}`,
			},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
			},
			{
				"Name": "Bob",
			},
		},
	}

	executeTestCase(t, test)
}
