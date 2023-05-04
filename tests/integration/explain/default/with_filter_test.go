// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain_default

import (
	"testing"

	explainUtils "github.com/sourcenetwork/defradb/tests/integration/explain"
)

func TestDefaultExplainRequestWithStringEqualFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with string equal (_eq) filter.",

		Request: `query @explain {
			Author(filter: {name: {_eq: "Lone"}}) {
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				// bae-bfbfc89c-0d63-5ea4-81a3-3ebd295be67f
				`{
					"name": "Lone",
					"age":  26,
					"verified": false
				}`,
				// "bae-079d0bd8-4b1b-5f5f-bd95-4d915c277f9d"
				`{
					"name":     "Shahzad Lone",
					"age":      27,
					"verified": true
				}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"name": dataMap{
							"_eq": "Lone",
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}

func TestDefaultExplainRequestWithIntegerEqualFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with integer equal (_eq) filter.",

		Request: `query @explain {
			Author(filter: {age: {_eq: 26}}) {
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				// bae-bfbfc89c-0d63-5ea4-81a3-3ebd295be67f
				`{
					"name": "Lone",
					"age":  26,
					"verified": false
				}`,
				// "bae-079d0bd8-4b1b-5f5f-bd95-4d915c277f9d"
				`{
					"name":     "Shahzad Lone",
					"age":      27,
					"verified": true
				}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"age": dataMap{
							"_eq": int(26),
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}

func TestDefaultExplainRequestWithGreaterThanFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with greater than (_gt) filter.",

		Request: `query @explain {
				Author(filter: {age: {_gt: 20}}) {
					name
					age
				}
			}`,

		Docs: map[int][]string{
			2: {
				// bae-bfbfc89c-0d63-5ea4-81a3-3ebd295be67f
				`{
						"name": "Lone",
						"age":  26,
						"verified": false
					}`,
				// "bae-079d0bd8-4b1b-5f5f-bd95-4d915c277f9d"
				`{
						"name":     "Shahzad Lone",
						"age":      27,
						"verified": true
					}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"age": dataMap{
							"_gt": int(20),
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}

func TestDefaultExplainRequestWithLogicalCompoundAndFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with logical compound (_and) filter.",

		Request: `query @explain {
			Author(filter: {_and: [{age: {_gt: 20}}, {age: {_lt: 50}}]}) {
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				`{
					"name": "John",
					"age": 21
				}`,
				`{
					"name": "Bob",
					"age": 32
				}`,
				`{
					"name": "Carlo",
					"age": 55
				}`,
				`{
					"name": "Alice",
					"age": 19
				}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"_and": []any{
							dataMap{
								"age": dataMap{
									"_gt": int(20),
								},
							},
							dataMap{
								"age": dataMap{
									"_lt": int(50),
								},
							},
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}

func TestDefaultExplainRequestWithLogicalCompoundOrFilter(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request with logical compound (_or) filter.",

		Request: `query @explain {
			Author(filter: {_or: [{age: {_eq: 55}}, {age: {_eq: 19}}]}) {
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				`{
					"name": "John",
					"age": 21
				}`,
				`{
					"name": "Bob",
					"age": 32
				}`,
				`{
					"name": "Carlo",
					"age": 55
				}`,
				`{
					"name": "Alice",
					"age": 19
				}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"_or": []any{
							dataMap{
								"age": dataMap{
									"_eq": int(55),
								},
							},
							dataMap{
								"age": dataMap{
									"_eq": int(19),
								},
							},
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}

func TestDefaultExplainRequestWithMatchInsideList(t *testing.T) {
	test := explainUtils.ExplainRequestTestCase{

		Description: "Explain (default) request filtering values that match within (_in) a list.",

		Request: `query @explain {
			Author(filter: {age: {_in: [19, 40, 55]}}) {
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				`{
					"name": "John",
					"age": 21
				}`,
				`{
					"name": "Bob",
					"age": 32
				}`,
				`{
					"name": "Carlo",
					"age": 55
				}`,
				`{
					"name": "Alice",
					"age": 19
				}`,
			},
		},

		ExpectedPatterns: []dataMap{basicPattern},

		ExpectedTargets: []explainUtils.PlanNodeTargetCase{
			{
				TargetNodeName:    "scanNode",
				IncludeChildNodes: true, // should be last node, so will have no child nodes.
				ExpectedAttributes: dataMap{
					"collectionID":   "3",
					"collectionName": "Author",
					"filter": dataMap{
						"age": dataMap{
							"_in": []any{
								int(19),
								int(40),
								int(55),
							},
						},
					},
					"spans": []dataMap{
						{
							"start": "/3",
							"end":   "/4",
						},
					},
				},
			},
		},
	}

	runExplainTest(t, test)
}
