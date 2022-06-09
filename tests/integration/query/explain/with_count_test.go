// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestExplainQueryOneToManyWithACount(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Explain one one-to-many relation query with count",
		Query: `query @explain {
				author {
					name
					numberOfBooks: _count(books: {})
				}
			}`,

		Docs: map[int][]string{
			//articles
			0: {
				(`{
					"name": "After Guantánamo, Another Injustice",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`),
				(`{
					"name": "To my dear readers",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
					}`),
				(`{
					"name": "Twinklestar's Favourite Xmas Cookie",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`),
			},
			//books
			1: {
				(`{
					"name": "Painted House",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`),
				(`{
					"name": "A Time for Mercy",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
				(`{
					"name": "Theif Lord",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`),
			},
			//authors
			2: {
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

		// ----> selectTopNode                (explainable but no-attributes)
		//     ----> countNode                (explainable)
		//         ----> selectNode           (explainable)
		//             ----> typeIndexJoin    (explainable)
		//                 ----> typeJoinMany (non-explainable)
		//                     ----> scanNode (explainable)
		Results: []dataMap{
			{
				"explain": dataMap{
					"selectTopNode": dataMap{
						"countNode": dataMap{
							"filter":         nil,
							"sourceProperty": "books",
							"selectNode": dataMap{
								"filter": nil,
								"typeIndexJoin": dataMap{
									"scanNode": dataMap{
										"collectionID":   "3",
										"collectionName": "author",
										"filter":         nil,
										"spans": []dataMap{
											{
												"start": "/3",
												"end":   "/4",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestExplainQueryOneToManyMultipleWithCounts(t *testing.T) {
	test := testUtils.QueryTestCase{

		Description: "Explain two one-to-many relation query with count",

		Query: `query @explain {
				author {
					name
					numberOfBooks: _count(books: {})
					numberOfArticles: _count(
						articles: {
							filter: {
								name: {
									_eq: "After Guantánamo, Another Injustice"
								}
							}
						}
					)
				}
			}`,

		Docs: map[int][]string{
			//articles
			0: {
				(`{
					"name": "After Guantánamo, Another Injustice",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`),
				(`{
					"name": "To my dear readers",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
					}`),
				(`{
					"name": "Twinklestar's Favourite Xmas Cookie",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`),
			},
			//books
			1: {
				(`{
					"name": "Painted House",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`),
				(`{
					"name": "A Time for Mercy",
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
				(`{
					"name": "Theif Lord",
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
				}`),
			},
			//authors
			2: {
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

		// ----> selectTopNode                             (explainable but no attributes)
		//     ----> countNode                             (explainable)
		//         ----> countNode                         (explainable)
		//             ----> selectNode                    (explainable)
		//                 ----> parallelNode              (non-explainable but wraps children)
		//                     ----> typeIndexJoin         (explainable)
		//                         ----> typeJoinMany      (non-explainable)
		//                             ----> multiscanNode (non-explainable)
		//                                 ----> scanNode  (explainable)
		//                     ----> typeIndexJoin         (explainable)
		//                         ----> typeJoinMany      (non-explainable)
		//                             ----> multiscanNode (non-explainable)
		//                                 ----> scanNode  (explainable)
		Results: []dataMap{
			{
				"explain": dataMap{
					"selectTopNode": dataMap{
						"countNode": dataMap{
							"filter":         nil,
							"sourceProperty": "books",
							"countNode": dataMap{
								"filter": dataMap{
									"name": dataMap{
										"$eq": "After Guantánamo, Another Injustice",
									},
								},
								"sourceProperty": "articles",
								"selectNode": dataMap{
									"filter": nil,
									"parallelNode": []dataMap{
										{
											"typeIndexJoin": dataMap{
												"scanNode": dataMap{
													"collectionID":   "3",
													"collectionName": "author",
													"filter":         nil,
													"spans": []dataMap{
														{
															"end":   "/4",
															"start": "/3",
														},
													},
												},
											},
										},
										{
											"typeIndexJoin": dataMap{
												"scanNode": dataMap{
													"collectionID":   "3",
													"collectionName": "author",
													"filter":         nil,
													"spans": []dataMap{
														{
															"end":   "/4",
															"start": "/3",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}
