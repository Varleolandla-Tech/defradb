// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package one_to_many

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryOneToManyWithCountAndLimitAndOffset(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-many relation query from many side with count and limit and offset",
		Query: `query {
				author {
					name
					_count(published: {})
					published(limit: 2, offset: 1) {
						name
					}
				}
			}`,
		Docs: map[int][]string{
			//books
			0: {
				`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				`{
					"name": "A Time for Mercy",
					"rating": 4.5,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`,
				`{
					"name": "The Firm",
					"rating": 4.1,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`,
				`{
					"name": "The Pelican Brief",
					"rating": 4.0,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`,
				`{
					"name": "Theif Lord",
					"rating": 4.8,
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`,
			},
			//authors
			1: {
				// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
				`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`,
				// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
				`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
				}`,
			},
		},
		Results: []map[string]interface{}{
			{
				"name":   "John Grisham",
				"_count": 4,
				"published": []map[string]interface{}{
					{
						"name": "The Pelican Brief",
					},
					{
						"name": "Painted House",
					},
				},
			},
			{
				"name":      "Cornelia Funke",
				"_count":    1,
				"published": []map[string]interface{}{},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryOneToManyWithCountAndDifferentOffsets(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-many relation query from many side with count and limit and offset",
		Query: `query {
				author {
					name
					_count(published: {offset: 1, limit: 2})
					published(limit: 2) {
						name
					}
				}
			}`,
		Docs: map[int][]string{
			//books
			0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
				`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				`{
					"name": "A Time for Mercy",
					"rating": 4.5,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				`{
					"name": "The Associate",
					"rating": 4.2,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				`{
					"name": "Theif Lord",
					"rating": 4.8,
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`,
			},
			//authors
			1: {
				// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
				`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`,
				// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
				`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
				}`,
			},
		},
		Results: []map[string]interface{}{
			{
				"name":   "John Grisham",
				"_count": 2,
				"published": []map[string]interface{}{
					{
						"name": "The Associate",
					},
					{
						"name": "Painted House",
					},
				},
			},
			{
				"name":   "Cornelia Funke",
				"_count": 0,
				"published": []map[string]interface{}{
					{
						"name": "Theif Lord",
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryOneToManyWithCountWithLimitWithOffset(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "One-to-many relation query from many side with count with limit with offset",
		Query: `query {
				author {
					name
					_count(published: {offset: 1, limit: 1})
				}
			}`,
		Docs: map[int][]string{
			//books
			0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
				`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				`{
					"name": "A Time for Mercy",
					"rating": 4.5,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`,
				`{
					"name": "Theif Lord",
					"rating": 4.8,
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`,
			},
			//authors
			1: {
				// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
				`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`,
				// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
				`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
				}`,
			},
		},
		Results: []map[string]interface{}{
			{
				"name":   "John Grisham",
				"_count": 1,
			},
			{
				"name":   "Cornelia Funke",
				"_count": 0,
			},
		},
	}

	executeTestCase(t, test)
}
