// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package schema

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestFilterForSimpleSchema(t *testing.T) {
	test := testUtils.TestCase{
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type users {
						name: String
					}
				`,
			},
			testUtils.IntrospectionRequest{
				Request: `
					query IntrospectionQuery {
						__schema {
							queryType {
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
													ofType {
														name
													}
												}
											}
										}
									}
								}
							}
						}
					}
				`,
				ContainsData: map[string]any{
					"__schema": map[string]any{
						"queryType": map[string]any{
							"fields": []any{
								map[string]any{
									"name": "users",
									"args": append(
										defaultUserArgsWithoutFilter,
										map[string]any{
											"name": "filter",
											"type": map[string]any{
												"name": "usersFilterArg",
												"inputFields": []any{
													map[string]any{
														"name": "_and",
														"type": map[string]any{
															"name": nil,
															"ofType": map[string]any{
																"name": "usersFilterArg",
															},
														},
													},
													map[string]any{
														"name": "_key",
														"type": map[string]any{
															"name":   "IDOperatorBlock",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "_not",
														"type": map[string]any{
															"name":   "usersFilterArg",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "_or",
														"type": map[string]any{
															"name": nil,
															"ofType": map[string]any{
																"name": "usersFilterArg",
															},
														},
													},
													map[string]any{
														"name": "name",
														"type": map[string]any{
															"name":   "StringOperatorBlock",
															"ofType": nil,
														},
													},
												},
											},
										},
									).tidy(),
								},
							},
						},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"users"}, test)
}

var testFilterForSimpleSchemaArgProps = map[string]any{
	"name": struct{}{},
	"type": map[string]any{
		"name":        struct{}{},
		"inputFields": struct{}{},
	},
}

var defaultUserArgsWithoutFilter = trimFields(
	fields{
		cidArg,
		dockeyArg,
		dockeysArg,
		groupByArg,
		limitArg,
		offsetArg,
		buildOrderArg("users", []argDef{
			{
				fieldName: "name",
				typeName:  "Ordering",
			},
		}),
	},
	testFilterForSimpleSchemaArgProps,
)

func TestFilterForOneToOneSchema(t *testing.T) {
	test := testUtils.TestCase{
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type book {
						name: String
						author: author
					}

					type author {
						age: Int
						wrote: book @primary
					}
				`,
			},
			testUtils.IntrospectionRequest{
				Request: `
					query IntrospectionQuery {
						__schema {
							queryType {
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
													ofType {
														name
													}
												}
											}
										}
									}
								}
							}
						}
					}
				`,
				ContainsData: map[string]any{
					"__schema": map[string]any{
						"queryType": map[string]any{
							"fields": []any{
								map[string]any{
									"name": "book",
									"args": append(
										defaultBookArgsWithoutFilter,
										map[string]any{
											"name": "filter",
											"type": map[string]any{
												"name": "bookFilterArg",
												"inputFields": []any{
													map[string]any{
														"name": "_and",
														"type": map[string]any{
															"name": nil,
															"ofType": map[string]any{
																"name": "bookFilterArg",
															},
														},
													},
													map[string]any{
														"name": "_key",
														"type": map[string]any{
															"name":   "IDOperatorBlock",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "_not",
														"type": map[string]any{
															"name":   "bookFilterArg",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "_or",
														"type": map[string]any{
															"name": nil,
															"ofType": map[string]any{
																"name": "bookFilterArg",
															},
														},
													},
													map[string]any{
														"name": "author",
														"type": map[string]any{
															"name":   "authorFilterArg",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "author_id",
														"type": map[string]any{
															"name":   "IDOperatorBlock",
															"ofType": nil,
														},
													},
													map[string]any{
														"name": "name",
														"type": map[string]any{
															"name":   "StringOperatorBlock",
															"ofType": nil,
														},
													},
												},
											},
										},
									).tidy(),
								},
							},
						},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, []string{"book", "author"}, test)
}

var testFilterForOneToOneSchemaArgProps = map[string]any{
	"name": struct{}{},
	"type": map[string]any{
		"name":        struct{}{},
		"inputFields": struct{}{},
	},
}

var defaultBookArgsWithoutFilter = trimFields(
	fields{
		cidArg,
		dockeyArg,
		dockeysArg,
		groupByArg,
		limitArg,
		offsetArg,
		buildOrderArg("book", []argDef{
			{
				fieldName: "author",
				typeName:  "authorOrderArg",
			},
			{
				fieldName: "author_id",
				typeName:  "Ordering",
			},
			{
				fieldName: "name",
				typeName:  "Ordering",
			},
		}),
	},
	testFilterForOneToOneSchemaArgProps,
)
