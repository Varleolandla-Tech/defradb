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

	"github.com/sourcenetwork/defradb/tests/integration/schema/defaults"
)

func TestFilterForSimpleSchema(t *testing.T) {
	test := QueryTestCase{
		Schema: []string{
			`
				type users {
					name: String
				}
			`,
		},
		IntrospectionQuery: `
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
							).Tidy(),
						},
					},
				},
			},
		},
	}

	ExecuteQueryTestCase(t, test)
}

var testFilterForSimpleSchemaArgProps = map[string]any{
	"name": struct{}{},
	"type": map[string]any{
		"name":        struct{}{},
		"inputFields": struct{}{},
	},
}

var defaultUserArgsWithoutFilter = defaults.TrimFields(
	defaults.Fields{
		defaults.DockeyArg,
		defaults.DockeysArg,
		defaults.CidArg,
		defaults.GroupByArg,
		defaults.LimitArg,
		defaults.OffsetArg,
		defaults.BuildAllOrderInputFields("users", []defaults.ArgDef{
			{
				FieldName: "name",
				TypeName:  "Ordering",
			},
		}),
	},
	testFilterForSimpleSchemaArgProps,
)

func TestFilterForOneToOneSchema(t *testing.T) {
	test := QueryTestCase{
		Schema: []string{
			`
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
		IntrospectionQuery: `
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
							).Tidy(),
						},
					},
				},
			},
		},
	}

	ExecuteQueryTestCase(t, test)
}

var testFilterForOneToOneSchemaArgProps = map[string]any{
	"name": struct{}{},
	"type": map[string]any{
		"name":        struct{}{},
		"inputFields": struct{}{},
	},
}

var defaultBookArgsWithoutFilter = defaults.TrimFields(
	defaults.Fields{
		defaults.CidArg,
		defaults.DockeyArg,
		defaults.DockeysArg,
		defaults.GroupByArg,
		defaults.LimitArg,
		defaults.OffsetArg,
		defaults.BuildAllOrderInputFields("book", []defaults.ArgDef{
			{
				FieldName: "author",
				TypeName:  "",
			},
			{
				FieldName: "author_id",
				TypeName:  "Ordering",
			},
			{
				FieldName: "name",
				TypeName:  "Ordering",
			},
		}),
	},
	testFilterForOneToOneSchemaArgProps,
)
