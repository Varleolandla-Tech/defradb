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

func TestQuerySimpleWithGroupByNumber(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by number, no children",
		Query: `query {
					users(groupBy: [Age]) {
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 32
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
				"Age": uint64(32),
			},
			{
				"Age": uint64(19),
			},
			{
				"Age": uint64(55),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByDateTime(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by number, no children",
		Query: `query {
					users(groupBy: [CreatedAt]) {
						CreatedAt
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"CreatedAt": "2011-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Bob",
					"CreatedAt": "2011-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Carlo",
					"CreatedAt": "2012-07-23T03:46:56.647Z"
				}`,
				`{
					"Name": "Alice",
					"CreatedAt": "2013-07-23T03:46:56.647Z"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"CreatedAt": "2013-07-23T03:46:56.647Z",
			},
			{
				"CreatedAt": "2011-07-23T03:46:56.647Z",
			},
			{
				"CreatedAt": "2012-07-23T03:46:56.647Z",
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByNumberWithGroupString(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by string, child string",
		Query: `query {
					users(groupBy: [Age]) {
						Age
						_group {
							Name
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 32
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
				"Age": uint64(32),
				"_group": []map[string]any{
					{
						"Name": "Bob",
					},
					{
						"Name": "John",
					},
				},
			},
			{
				"Age": uint64(19),
				"_group": []map[string]any{
					{
						"Name": "Alice",
					},
				},
			},
			{
				"Age": uint64(55),
				"_group": []map[string]any{
					{
						"Name": "Carlo",
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByString(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by string",
		Query: `query {
					users(groupBy: [Name]) {
						Name
						_group {
							Age
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 25
				}`,
				`{
					"Name": "John",
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
				"_group": []map[string]any{
					{
						"Age": uint64(19),
					},
				},
			},
			{
				"Name": "John",
				"_group": []map[string]any{
					{
						"Age": uint64(32),
					},
					{
						"Age": uint64(25),
					},
				},
			},
			{
				"Name": "Carlo",
				"_group": []map[string]any{
					{
						"Age": uint64(55),
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByStringWithInnerGroupBoolean(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by string, with child group by boolean",
		Query: `query {
					users(groupBy: [Name]) {
						Name
						_group (groupBy: [Verified]){
							Verified
							_group {
								Age
							}
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 25,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 32,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 34,
					"Verified": false
				}`,
				`{
					"Name": "Carlo",
					"Age": 55,
					"Verified": true
				}`,
				`{
					"Name": "Alice",
					"Age": 19,
					"Verified": false
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name": "John",
				"_group": []map[string]any{
					{
						"Verified": true,
						"_group": []map[string]any{
							{
								"Age": uint64(25),
							},
							{
								"Age": uint64(32),
							},
						},
					},
					{
						"Verified": false,
						"_group": []map[string]any{
							{
								"Age": uint64(34),
							},
						},
					},
				},
			},
			{
				"Name": "Alice",
				"_group": []map[string]any{
					{
						"Verified": false,
						"_group": []map[string]any{
							{
								"Age": uint64(19),
							},
						},
					},
				},
			},
			{
				"Name": "Carlo",
				"_group": []map[string]any{
					{
						"Verified": true,
						"_group": []map[string]any{
							{
								"Age": uint64(55),
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByStringThenBoolean(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by string then by boolean",
		Query: `query {
					users(groupBy: [Name, Verified]) {
						Name
						Verified
						_group {
							Age
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 25,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 32,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 34,
					"Verified": false
				}`,
				`{
					"Name": "Carlo",
					"Age": 55,
					"Verified": true
				}`,
				`{
					"Name": "Alice",
					"Age": 19,
					"Verified": false
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name":     "John",
				"Verified": true,
				"_group": []map[string]any{
					{
						"Age": uint64(25),
					},
					{
						"Age": uint64(32),
					},
				},
			},
			{
				"Name":     "John",
				"Verified": false,
				"_group": []map[string]any{
					{
						"Age": uint64(34),
					},
				},
			},
			{
				"Name":     "Alice",
				"Verified": false,
				"_group": []map[string]any{
					{
						"Age": uint64(19),
					},
				},
			},
			{
				"Name":     "Carlo",
				"Verified": true,
				"_group": []map[string]any{
					{
						"Age": uint64(55),
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByBooleanThenNumber(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by boolean then by string",
		Query: `query {
					users(groupBy: [Verified, Name]) {
						Name
						Verified
						_group {
							Age
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 25,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 32,
					"Verified": true
				}`,
				`{
					"Name": "John",
					"Age": 34,
					"Verified": false
				}`,
				`{
					"Name": "Carlo",
					"Age": 55,
					"Verified": true
				}`,
				`{
					"Name": "Alice",
					"Age": 19,
					"Verified": false
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name":     "John",
				"Verified": true,
				"_group": []map[string]any{
					{
						"Age": uint64(25),
					},
					{
						"Age": uint64(32),
					},
				},
			},
			{
				"Name":     "John",
				"Verified": false,
				"_group": []map[string]any{
					{
						"Age": uint64(34),
					},
				},
			},
			{
				"Name":     "Alice",
				"Verified": false,
				"_group": []map[string]any{
					{
						"Age": uint64(19),
					},
				},
			},
			{
				"Name":     "Carlo",
				"Verified": true,
				"_group": []map[string]any{
					{
						"Age": uint64(55),
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByNumberOnUndefined(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by number, no children, undefined group value",
		Query: `query {
					users(groupBy: [Age]) {
						Age
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 32
				}`,
				`{
					"Name": "Bob"
				}`,
				`{
					"Name": "Alice"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Age": nil,
			},
			{
				"Age": uint64(32),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithGroupByNumberOnUndefinedWithChildren(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by number, with children, undefined group value",
		Query: `query {
					users(groupBy: [Age]) {
						Age
						_group {
							Name
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 32
				}`,
				`{
					"Name": "Bob"
				}`,
				`{
					"Name": "Alice"
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Age": nil,
				"_group": []map[string]any{
					{
						"Name": "Bob",
					},
					{
						"Name": "Alice",
					},
				},
			},
			{
				"Age": uint64(32),
				"_group": []map[string]any{
					{
						"Name": "John",
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleErrorsWithNonGroupFieldsSelected(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Simple query with group by number, no children",
		Query: `query {
					users(groupBy: [Age]) {
						Age
						Name
					}
				}`,
		Docs:          map[int][]string{},
		ExpectedError: "cannot select a non-group-by field at group-level",
	}

	executeTestCase(t, test)
}
