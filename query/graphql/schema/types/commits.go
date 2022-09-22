// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package types

import (
	gql "github.com/graphql-go/graphql"

	parserTypes "github.com/sourcenetwork/defradb/query/graphql/parser/types"
)

var (
	// Helper only for `commit` below.
	commitCountFieldArg = gql.NewEnum(gql.EnumConfig{
		Name: "commitCountFieldArg",
		Values: gql.EnumValueConfigMap{
			"links": &gql.EnumValueConfig{Value: "links"},
		},
	})

	// Commit represents an individual commit to a MerkleCRDT
	// type Commit {
	// 	Height: Int
	// 	CID: String
	// 	Delta: String
	// 	Previous: [Commit]
	//  Links: [Commit]
	// }
	//
	// Any self referential type needs to be initalized
	// inside the init() func
	CommitObject = gql.NewObject(gql.ObjectConfig{
		Name: "Commit",
		Fields: gql.Fields{
			"height": &gql.Field{
				Type: gql.Int,
			},
			"cid": &gql.Field{
				Type: gql.String,
			},
			"delta": &gql.Field{
				Type: gql.String,
			},
			"links": &gql.Field{
				Type: gql.NewList(CommitLinkObject),
			},
			"_count": &gql.Field{
				Type: gql.Int,
				Args: gql.FieldConfigArgument{
					"field": &gql.ArgumentConfig{
						Type: commitCountFieldArg,
					},
				},
			},
		},
	})

	// Delta represents a Delta State update for a CRDT
	// type Delta {
	// 	Payload: String
	// }
	DeltaObject = gql.NewObject(gql.ObjectConfig{
		Name: "Delta",
		Fields: gql.Fields{
			"payload": &gql.Field{
				Type: gql.String,
			},
		},
	})

	// CommitLink is a named DAG link between commits.
	// This is primary used for CompositeDAG CRDTs
	CommitLinkObject = gql.NewObject(gql.ObjectConfig{
		Name: "CommitLink",
		Fields: gql.Fields{
			"name": &gql.Field{
				Type: gql.String,
			},
			"cid": &gql.Field{
				Type: gql.String,
			},
		},
	})

	AllCommitsOrderArg = gql.NewInputObject(
		gql.InputObjectConfig{
			Name: "allCommitsOrderArg",
			Fields: gql.InputObjectConfigFieldMap{
				"height": &gql.InputObjectFieldConfig{
					Type: OrderingEnum,
				},
				"cid": &gql.InputObjectFieldConfig{
					Type: OrderingEnum,
				},
			},
		},
	)

	QueryAllCommits = &gql.Field{
		Name: "allCommits",
		Type: gql.NewList(CommitObject),
		Args: gql.FieldConfigArgument{
			"dockey":                NewArgConfig(gql.NewNonNull(gql.ID)),
			"field":                 NewArgConfig(gql.String),
			"order":                 NewArgConfig(AllCommitsOrderArg),
			parserTypes.LimitClause: NewArgConfig(gql.Int),
		},
	}

	QueryLatestCommits = &gql.Field{
		Name: "latestCommits",
		Type: gql.NewList(CommitObject),
		Args: gql.FieldConfigArgument{
			"dockey": NewArgConfig(gql.NewNonNull(gql.ID)),
			"field":  NewArgConfig(gql.String),
		},
	}

	QueryCommit = &gql.Field{
		Name: "commit",
		Type: CommitObject,
		Args: gql.FieldConfigArgument{
			"cid": NewArgConfig(gql.NewNonNull(gql.ID)),
		},
	}
)
