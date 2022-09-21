// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package one_to_one

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryOneToOne(t *testing.T) {
	tests := []testUtils.QueryTestCase{
		{
			Description: "One-to-one relation query with no filter",
			Query: `query {
						book {
							name
							rating
							author {
								name
								age
							}
						}
					}`,
			Docs: map[int][]string{
				//books
				0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					`{
						"name": "Painted House",
						"rating": 4.9
					}`,
				},
				//authors
				1: { // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					`{
						"name": "John Grisham",
						"age": 65,
						"verified": true,
						"published_id": "bae-fd541c25-229e-5280-b44b-e5c2af3e374d"
					}`,
				},
			},
			Results: []map[string]any{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]any{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			Description: "One-to-one relation secondary direction, no filter",
			Query: `query {
						author {
							name
							age
							published {
								name
								rating
							}
						}
					}`,
			Docs: map[int][]string{
				//books
				0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					`{
						"name": "Painted House",
						"rating": 4.9
					}`,
				},
				//authors
				1: { // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					`{
						"name": "John Grisham",
						"age": 65,
						"verified": true,
						"published_id": "bae-fd541c25-229e-5280-b44b-e5c2af3e374d"
					}`,
				},
			},
			Results: []map[string]any{
				{
					"name": "John Grisham",
					"age":  uint64(65),
					"published": map[string]any{
						"name":   "Painted House",
						"rating": 4.9,
					},
				},
			},
		},
	}

	for _, test := range tests {
		executeTestCase(t, test)
	}
}

func TestQueryOneToOneWithMultipleRecords(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-one relation primary direction, multiple records",
		Query: `query {
			book {
				name
				author {
					name
				}
			}
		}`,
		Docs: map[int][]string{
			//books
			0: {
				// bae-fd541c25-229e-5280-b44b-e5c2af3e374d
				`{
					"name": "Painted House",
					"rating": 4.9
				}`,
				// "bae-d3bc0f38-a2e1-5a26-9cc9-5b3fdb41c6db"
				`{
					"name": "Go Guide for Rust developers",
					"rating": 5.0
				}`,
			},
			//authors
			1: {
				// "bae-3bfe0092-e31f-5ebe-a3ba-fa18fac448a6"
				`{
					"name": "John Grisham",
					"age": 65,
					"verified": true,
					"published_id": "bae-fd541c25-229e-5280-b44b-e5c2af3e374d"
				}`,
				// "bae-756c2bf0-4767-57fd-b12b-393915feae68",
				`{
					"name": "Andrew Lone",
					"age": 30,
					"verified": true,
					"published_id": "bae-d3bc0f38-a2e1-5a26-9cc9-5b3fdb41c6db"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"name": "Go Guide for Rust developers",
				"author": map[string]any{
					"name": "Andrew Lone",
				},
			},
			{
				"name": "Painted House",
				"author": map[string]any{
					"name": "John Grisham",
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryOneToOneWithNilChild(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-one relation primary direction, nil child",
		Query: `query {
			author {
				name
				published {
					name
				}
			}
		}`,
		Docs: map[int][]string{
			//authors
			1: {
				`{
					"name": "John Grisham"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"name":      "John Grisham",
				"published": nil,
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryOneToOneWithNilParent(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-one relation primary direction, nil parent",
		Query: `query {
			book {
				name
				author {
					name
				}
			}
		}`,
		Docs: map[int][]string{
			//books
			0: {
				`{
					"name": "Painted House"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"name":   "Painted House",
				"author": nil,
			},
		},
	}

	executeTestCase(t, test)
}
