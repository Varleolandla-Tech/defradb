// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package one_to_many_to_one

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryOneToOneRelations(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Multiple One-to-one relations query with no filter.",
		Request: `query {
			Book {
				name
				author {
					name
				}
				publisher {
					name
				}
			}
		}`,

		Docs: map[int][]string{
			// Authors
			0: {
				// bae-41598f0c-19bc-5da6-813b-e80f14a10df3, Has written 5 books
				`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`,
				// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04, Has written 1 book
				`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
				}`,
				// Has written no book
				`{
					"name": "Not a Writer",
					"age": 6,
					"verified": false
				}`,
			},

			// Books
			1: {
				// "bae-b6c078f2-3427-5b99-bafd-97dcd7c2e935", Has 1 publisher
				`{
					"name": "The Rooster Bar",
					"rating": 4,
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`,
				// "bae-b8091c4f-7594-5d7a-98e8-272aadcedfdf", Has 1 publisher
				`{
					"name": "Theif Lord",
					"rating": 4.8,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
				// "bae-4fb9e3e9-d1d3-5404-bf15-10e4c995d9ca", Has no publisher.
				`{
					"name": "The Associate",
					"rating": 4.2,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`,
			},

			// Publishers
			2: {
				`{
					"name": "Only Publisher of The Rooster Bar",
					"address": "1 Rooster Ave., Waterloo, Ontario",
					"yearOpened": 2022,
					"book_id": "bae-b6c078f2-3427-5b99-bafd-97dcd7c2e935"
			    }`,
				`{
					"name": "Only Publisher of Theif Lord",
					"address": "1 Theif Lord, Waterloo, Ontario",
					"yearOpened": 2020,
					"book_id": "bae-b8091c4f-7594-5d7a-98e8-272aadcedfdf"
			    }`,
			},
		},

		Results: []map[string]any{
			{
				"name": "The Associate",
				"author": map[string]any{
					"name": "John Grisham",
				},
				"publisher": nil,
			},
			{
				"name": "The Rooster Bar",
				"author": map[string]any{
					"name": "Cornelia Funke",
				},
				"publisher": map[string]any{
					"name": "Only Publisher of The Rooster Bar",
				},
			},
			{
				"name": "Theif Lord",
				"author": map[string]any{
					"name": "John Grisham",
				},
				"publisher": map[string]any{
					"name": "Only Publisher of Theif Lord",
				},
			},
		},
	}

	executeTestCase(t, test)
}
