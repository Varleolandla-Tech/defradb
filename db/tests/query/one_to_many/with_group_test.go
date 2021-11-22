// Copyright 2020 Source Inc.
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

	testUtils "github.com/sourcenetwork/defradb/db/tests"
)

func TestQueryOneToManyWithInnerJoinGroupNumber(t *testing.T) {
	tests := []testUtils.QueryTestCase{
		{
			Description: "One-to-many relation query from many side with group inside of join",
			Query: `query {
				author {
					name
					age
					published (groupBy: [rating]){
						rating
						_group {
							name
						}
					}
				}
			}`,
			Docs: map[int][]string{
				//books
				0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
						"name": "Painted House",
						"rating": 4.9,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
					(`{
						"name": "A Time for Mercy",
						"rating": 4.5,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
						}`),
					(`{
						"name": "The Client",
						"rating": 4.5,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
						}`),
					(`{
						"name": "Theif Lord",
						"rating": 4.8,
						"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
					}`),
				},
				//authors
				1: {
					// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
						"name": "John Grisham",
						"age": 65,
						"verified": true
					}`),
					// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
					(`{
						"name": "Cornelia Funke",
						"age": 62,
						"verified": false
					}`),
				},
			},
			Results: []map[string]interface{}{
				{
					"name": "John Grisham",
					"age":  uint64(65),
					"published": []map[string]interface{}{
						{
							"rating": 4.5,
							"_group": []map[string]interface{}{
								{
									"name": "The Client",
								},
								{
									"name": "A Time for Mercy",
								},
							},
						},
						{
							"rating": 4.9,
							"_group": []map[string]interface{}{
								{
									"name": "Painted House",
								},
							},
						},
					},
				},
				{
					"name": "Cornelia Funke",
					"age":  uint64(62),
					"published": []map[string]interface{}{
						{
							"rating": 4.8,
							"_group": []map[string]interface{}{
								{
									"name": "Theif Lord",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		executeTestCase(t, test)
	}
}

func TestQueryOneToManyWithParentJoinGroupNumber(t *testing.T) {
	tests := []testUtils.QueryTestCase{
		{
			Description: "One-to-many relation query from many side with parent level group",
			Query: `query {
				author (groupBy: [age]) {
					age
					_group {
						name
						published {
							name
							rating
						}
					}
				}
			}`,
			Docs: map[int][]string{
				//books
				0: { // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
						"name": "Painted House",
						"rating": 4.9,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
					(`{
						"name": "A Time for Mercy",
						"rating": 4.5,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
						}`),
					(`{
						"name": "The Client",
						"rating": 4.5,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
						}`),
					(`{
						"name": "Candide",
						"rating": 4.95,
						"author_id": "bae-7accaba8-ea9d-54b1-92f4-4a7ac5de88b3"
					}`),
					(`{
						"name": "Zadig",
						"rating": 4.91,
						"author_id": "bae-7accaba8-ea9d-54b1-92f4-4a7ac5de88b3"
					}`),
					(`{
						"name": "Histoiare des Celtes et particulierement des Gaulois et des Germains depuis les temps fabuleux jusqua la prise de Roze par les Gaulois",
						"rating": 2,
						"author_id": "bae-09d33399-197a-5b98-b135-4398f2b6de4c"
					}`),
				},
				//authors
				1: {
					// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
						"name": "John Grisham",
						"age": 65,
						"verified": true
					}`),
					// bae-7accaba8-ea9d-54b1-92f4-4a7ac5de88b3
					(`{
						"name": "Voltaire",
						"age": 327,
						"verified": true
					}`),
					// bae-09d33399-197a-5b98-b135-4398f2b6de4c
					(`{
						"name": "Simon Pelloutier",
						"age": 327,
						"verified": true
					}`),
				},
			},
			Results: []map[string]interface{}{
				{
					"age": uint64(327),
					"_group": []map[string]interface{}{
						{
							"name": "Simon Pelloutier",
							"published": []map[string]interface{}{
								{
									"name":   "Histoiare des Celtes et particulierement des Gaulois et des Germains depuis les temps fabuleux jusqua la prise de Roze par les Gaulois",
									"rating": uint64(2),
								},
							},
						},
						{
							"name": "Voltaire",
							"published": []map[string]interface{}{
								{
									"name":   "Candide",
									"rating": 4.95,
								},
								{
									"name":   "Zadig",
									"rating": 4.91,
								},
							},
						},
					},
				},
				{
					"age": uint64(65),
					"_group": []map[string]interface{}{
						{
							"name": "John Grisham",
							"published": []map[string]interface{}{
								{
									"name":   "The Client",
									"rating": 4.5,
								},
								{
									"name":   "Painted House",
									"rating": 4.9,
								},
								{
									"name":   "A Time for Mercy",
									"rating": 4.5,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		executeTestCase(t, test)
	}
}
