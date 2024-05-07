// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package index

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryWithIndexOnOneToManyRelation_IfFilterOnIndexedRelation_ShouldFilter2(t *testing.T) {
	req1 := `query {
		User(filter: {
			devices: {model: {_eq: "MacBook Pro"}}
		}) {
			name
		}
	}`
	req2 := `query {
		User(filter: {
			devices: {model: {_eq: "iPhone 10"}}
		}) {
			name
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed relation field in 1-N relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String 
						age: Int
						devices: [Device] 
					} 

					type Device {
						model: String @index
						owner: User
					}`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req1,
				Results: []map[string]any{
					{"name": "Keenan"},
					{"name": "Islam"},
					{"name": "Shahzad"},
				},
			},
			testUtils.Request{
				Request: makeExplainQuery(req1),
				// The invertable join does not support inverting one-many relations, so the index is
				// not used.
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(450).WithIndexFetches(0),
			},
			testUtils.Request{
				Request: req2,
				Results: []map[string]any{
					{"name": "Addo"},
				},
			},
			testUtils.Request{
				Request: makeExplainQuery(req2),
				// The invertable join does not support inverting one-many relations, so the index is
				// not used.
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(450).WithIndexFetches(0),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToManyRelation_IfFilterOnIndexedRelation_ShouldFilter(t *testing.T) {
	req1 := `query {
		User(filter: {
			devices: {model: {_eq: "MacBook Pro"}}
		}) {
			name
		}
	}`
	req2 := `query {
		User(filter: {
			devices: {model: {_eq: "iPhone 10"}}
		}) {
			name
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed relation field in 1-N relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String 
						age: Int
						devices: [Device] 
					} 

					type Device {
						model: String @index
						owner: User
					}`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req1,
				Results: []map[string]any{
					{"name": "Keenan"},
					{"name": "Islam"},
					{"name": "Shahzad"},
				},
			},
			testUtils.Request{
				Request: makeExplainQuery(req1),
				// The invertable join does not support inverting one-many relations, so the index is
				// not used.
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(450).WithIndexFetches(0),
			},
			testUtils.Request{
				Request: req2,
				Results: []map[string]any{
					{"name": "Addo"},
				},
			},
			testUtils.Request{
				Request: makeExplainQuery(req2),
				// The invertable join does not support inverting one-many relations, so the index is
				// not used.
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(450).WithIndexFetches(0),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToOnesSecondaryRelation_IfFilterOnIndexedRelation_ShouldFilter(t *testing.T) {
	req1 := `query {
		User(filter: {
			address: {city: {_eq: "Munich"}}
		}) {
			name
		}
	}`
	req2 := `query {
		User(filter: {
			address: {city: {_eq: "Montreal"}}
		}) {
			name
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed secondary relation field in 1-1 relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String 
						age: Int
						address: Address
					} 

					type Address {
						user: User @primary
						city: String @index
					}`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req1,
				Results: []map[string]any{
					{"name": "Islam"},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req1),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(2).WithIndexFetches(1),
			},
			testUtils.Request{
				Request: req2,
				Results: []map[string]any{
					{"name": "Shahzad"},
					{"name": "Fred"},
					{"name": "John"},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req2),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(6).WithIndexFetches(3),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToOnePrimaryRelation_IfFilterOnIndexedFieldOfRelation_ShouldFilter(t *testing.T) {
	req1 := `query {
		User(filter: {
			address: {city: {_eq: "London"}}
		}) {
			name
		}
	}`
	req2 := `query {
		User(filter: {
			address: {city: {_eq: "Montreal"}}
		}) {
			name
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed field of primary relation in 1-1 relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String 
						age: Int
						address: Address @primary 
					} 

					type Address {
						user: User
						city: String @index
						street: String 
					}`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req1,
				Results: []map[string]any{
					{"name": "Andy"},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req1),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(11).WithIndexFetches(1),
			},
			testUtils.Request{
				Request: req2,
				Results: []map[string]any{
					{"name": "John"},
					{"name": "Fred"},
					{"name": "Shahzad"},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req2),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(15).WithIndexFetches(3),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToOnePrimaryRelation_IfFilterOnIndexedRelationWhileIndexedForeignField_ShouldFilter(t *testing.T) {
	req := `query {
		User(filter: {
			address: {city: {_eq: "London"}}
		}) {
			name
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed field of primary relation while having indexed foreign field in 1-1 relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String 
						age: Int
						address: Address @primary @index
					} 

					type Address {
						user: User
						city: String @index
						street: String 
					}`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req,
				Results: []map[string]any{
					{"name": "Andy"},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(11).WithIndexFetches(1),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToMany_IfFilterOnIndexedRelation_ShouldFilter(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Filter on indexed relation field in 1-N relations",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String
						devices: [Device]
					}

					type Device {
						model: String @index
						manufacturer: String
						owner: User
					}
				`,
			},
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
					"name":	"Chris"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
					"name":	"Addo"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Walkman",
					"manufacturer": "Sony",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Walkman",
					"manufacturer": "The Proclaimers",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Running Man",
					"manufacturer": "Braveworld Productions",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.Request{
				Request: `query {
					User(filter: {
						devices: {model: {_eq: "Walkman"}}
					}) {
						name
						devices {
							model
							manufacturer
						}
					}
				}`,
				Results: []map[string]any{
					{
						"name": "Chris",
						"devices": []map[string]any{
							{
								"model":        "Walkman",
								"manufacturer": "Sony",
							},
							{
								"model":        "Walkman",
								"manufacturer": "The Proclaimers",
							},
							// The filter is on User, so all devices belonging to it will be returned
							{
								"model":        "Running Man",
								"manufacturer": "Braveworld Productions",
							},
						},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToMany_IfFilterOnIndexedRelation_ShouldFilterWithExplain(t *testing.T) {
	req := `query {
		User(filter: {
			devices: {model: {_eq: "Walkman"}}
		}) {
			name
			devices {
				model
				manufacturer
			}
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed relation field in 1-N relations",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String
						devices: [Device]
					} 

					type Device {
						model: String @index
						manufacturer: String
						owner: User
					}
				`,
			},
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
					"name":	"Chris"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Walkman",
					"manufacturer": "Sony",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Walkman",
					"manufacturer": "The Proclaimers",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.CreateDoc{
				CollectionID: 1,
				Doc: `{
					"model":	"Running Man",
					"manufacturer": "Braveworld Productions",
					"owner": "bae-403d7337-f73e-5c81-8719-e853938c8985"
				}`,
			},
			testUtils.Request{
				Request: req,
				Results: []map[string]any{
					{
						"name": "Chris",
						"devices": []map[string]any{
							{
								"model":        "Walkman",
								"manufacturer": "Sony",
							},
							{
								"model":        "Walkman",
								"manufacturer": "The Proclaimers",
							},
							{
								"model":        "Running Man",
								"manufacturer": "Braveworld Productions",
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: makeExplainQuery(req),
				// The invertable join does not support inverting one-many relations, so the index is
				// not used.
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(10).WithIndexFetches(0),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQueryWithIndexOnOneToOne_IfFilterOnIndexedRelation_ShouldFilter(t *testing.T) {
	req := `query {
		User(filter: {
			address: {city: {_eq: "Munich"}}
		}) {
			name
			address {
				city
			}
		}
	}`
	test := testUtils.TestCase{
		Description: "Filter on indexed relation field in 1-1 relation",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type User {
						name: String
						address: Address
					}

					type Address {
						user: User @primary
						city: String @index
					}
				`,
			},
			testUtils.CreatePredefinedDocs{
				Docs: getUserDocs(),
			},
			testUtils.Request{
				Request: req,
				Results: []map[string]any{
					{
						"name": "Islam",
						"address": map[string]any{
							"city": "Munich",
						},
					},
				},
			},
			testUtils.Request{
				Request:  makeExplainQuery(req),
				Asserter: testUtils.NewExplainAsserter().WithFieldFetches(2).WithIndexFetches(1),
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
