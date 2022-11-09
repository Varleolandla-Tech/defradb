// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package request

import (
	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/events"
)

// ObjectSubscription is a field on the SubscriptionType
// of a graphql query. It includes all the possible
// arguments
type ObjectSubscription struct {
	Field

	DocKeys client.Option[[]string]
	CID     client.Option[string]

	// Schema is the target schema/collection
	Schema string

	Filter client.Option[Filter]

	Fields []Selection

	Stream *events.Publisher
}

// ToSelect returns a basic Select object, with the same Name, Alias, and Fields as
// the Subscription object. Used to create a Select planNode for the event stream return objects.
func (m ObjectSubscription) ToSelect() *Select {
	return &Select{
		Field: Field{
			Name:  m.Schema,
			Alias: m.Alias,
		},
		DocKeys: m.DocKeys,
		CID:     m.CID,
		Fields:  m.Fields,
		Filter:  m.Filter,
	}
}
