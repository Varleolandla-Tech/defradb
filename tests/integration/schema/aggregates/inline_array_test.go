// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package aggregates

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration/schema"
)

func TestSchemaAggregateInlineArrayCreatesUsersCount(t *testing.T) {
	test := testUtils.QueryTestCase{
		Schema: []string{
			`
				type users {
					FavouriteIntegers: [Int!]
				}
			`,
		},
		IntrospectionQuery: `
			query IntrospectionQuery {
				__type (name: "users") {
					name
					fields {
						name
						args {
							name
							type {
								name
								inputFields {
									name
									type {
										name
									}
								}
							}
						}
					}
				}
			}
		`,
		ContainsData: map[string]interface{}{
			"__type": map[string]interface{}{
				"name": "users",
				"fields": []interface{}{
					map[string]interface{}{
						"name": "_count",
						"args": []interface{}{
							map[string]interface{}{
								"name": "FavouriteIntegers",
								"type": map[string]interface{}{
									"name": "users__FavouriteIntegers__CountSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "_",
											"type": map[string]interface{}{
												"name": "Int",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "NotNullIntOperatorBlock",
											},
										},
									},
								},
							},
							map[string]interface{}{
								"name": "_group",
								"type": map[string]interface{}{
									"name": "users__CountSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "_",
											"type": map[string]interface{}{
												"name": "Int",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "usersFilterArg",
											},
										},
									},
								},
							},
							map[string]interface{}{
								"name": "_version",
								"type": map[string]interface{}{
									"name": "users___version__CountSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "_",
											"type": map[string]interface{}{
												"name": "Int",
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

	testUtils.ExecuteQueryTestCase(t, test)
}

func TestSchemaAggregateInlineArrayCreatesUsersSum(t *testing.T) {
	test := testUtils.QueryTestCase{
		Schema: []string{
			`
				type users {
					FavouriteFloats: [Float!]
				}
			`,
		},
		IntrospectionQuery: `
			query IntrospectionQuery {
				__type (name: "users") {
					name
					fields {
						name
						args {
							name
							type {
								name
								inputFields {
									name
									type {
										name
									}
								}
							}
						}
					}
				}
			}
		`,
		ContainsData: map[string]interface{}{
			"__type": map[string]interface{}{
				"name": "users",
				"fields": []interface{}{
					map[string]interface{}{
						"name": "_sum",
						"args": []interface{}{
							map[string]interface{}{
								"name": "FavouriteFloats",
								"type": map[string]interface{}{
									"name": "users__FavouriteFloats__NumericSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "_",
											"type": map[string]interface{}{
												"name": "Int",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "NotNullFloatOperatorBlock",
											},
										},
									},
								},
							},
							map[string]interface{}{
								"name": "_group",
								"type": map[string]interface{}{
									"name": "users__NumericSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "field",
											"type": map[string]interface{}{
												"name": "usersNumericFieldsArg",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "usersFilterArg",
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

	testUtils.ExecuteQueryTestCase(t, test)
}

func TestSchemaAggregateInlineArrayCreatesUsersAverage(t *testing.T) {
	test := testUtils.QueryTestCase{
		Schema: []string{
			`
				type users {
					FavouriteIntegers: [Int!]
				}
			`,
		},
		IntrospectionQuery: `
			query IntrospectionQuery {
				__type (name: "users") {
					name
					fields {
						name
						args {
							name
							type {
								name
								inputFields {
									name
									type {
										name
									}
								}
							}
						}
					}
				}
			}
		`,
		ContainsData: map[string]interface{}{
			"__type": map[string]interface{}{
				"name": "users",
				"fields": []interface{}{
					map[string]interface{}{
						"name": "_avg",
						"args": []interface{}{
							map[string]interface{}{
								"name": "FavouriteIntegers",
								"type": map[string]interface{}{
									"name": "users__FavouriteIntegers__NumericSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "_",
											"type": map[string]interface{}{
												"name": "Int",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "NotNullIntOperatorBlock",
											},
										},
									},
								},
							},
							map[string]interface{}{
								"name": "_group",
								"type": map[string]interface{}{
									"name": "users__NumericSelector",
									"inputFields": []interface{}{
										map[string]interface{}{
											"name": "field",
											"type": map[string]interface{}{
												"name": "usersNumericFieldsArg",
											},
										},
										map[string]interface{}{
											"name": "filter",
											"type": map[string]interface{}{
												"name": "usersFilterArg",
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

	testUtils.ExecuteQueryTestCase(t, test)
}
