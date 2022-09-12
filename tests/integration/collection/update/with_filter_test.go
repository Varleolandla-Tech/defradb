// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package update

import (
	"context"
	"testing"

	"github.com/sourcenetwork/defradb/client"
	testUtils "github.com/sourcenetwork/defradb/tests/integration/collection"
	"github.com/stretchr/testify/assert"
)

func TestUpdateWithFilter(t *testing.T) {
	doc, err := client.NewDocFromJSON(
		[]byte(
			`{
				"Name": "John",
				"Age": 21
			}`,
		),
	)
	if err != nil {
		assert.Fail(t, err.Error())
	}

	filter := `{Name: {_eq: "John"}}`

	tests := []testUtils.TestCase{
		{
			Description: "Test update users with filter and invalid JSON",
			Docs: map[string][]string{
				"users": {
					`{
						"Name": "John",
						"Age": 21
					}`,
				},
			},
			CollectionCalls: map[string][]func(client.Collection) error{
				"users": []func(c client.Collection) error{
					func(c client.Collection) error {
						ctx := context.Background()
						_, err := c.UpdateWithFilter(ctx, filter, `{
							Name: "Eric"
						}`)
						return err
					},
				},
			},
			ExpectedError: "cannot parse JSON: cannot parse object: cannot find opening '\"\" for object key; unparsed tail: \"Name: \\\"Eric\\\"\\n\\t\\t\\t\\t\\t\\t}\"",
		}, {
			Description: "Test update users with filter and invalid updator",
			Docs: map[string][]string{
				"users": {
					`{
						"Name": "John",
						"Age": 21
					}`,
				},
			},
			CollectionCalls: map[string][]func(client.Collection) error{
				"users": []func(c client.Collection) error{
					func(c client.Collection) error {
						ctx := context.Background()
						_, err := c.UpdateWithFilter(ctx, filter, `"Name: Eric"`)
						return err
					},
				},
			},
			ExpectedError: "The updater of a document is of invalid type",
		}, {
			Description: "Test update users with filter and patch updator (not implemented so no change)",
			Docs: map[string][]string{
				"users": {
					`{
						"Name": "John",
						"Age": 21
					}`,
				},
			},
			CollectionCalls: map[string][]func(client.Collection) error{
				"users": []func(c client.Collection) error{
					func(c client.Collection) error {
						ctx := context.Background()
						_, err := c.UpdateWithFilter(ctx, filter, `[
							{
								"Name": "Eric"
							}, {
								"Name": "Sam"
							}
						]`)
						if err != nil {
							return err
						}

						d, err := c.Get(ctx, doc.Key())
						if err != nil {
							return err
						}

						name, err := d.Get("Name")
						if err != nil {
							return err
						}

						assert.Equal(t, "John", name)

						return nil
					},
				},
			},
		}, {
			Description: "Test update users with filter",
			Docs: map[string][]string{
				"users": {
					`{
						"Name": "John",
						"Age": 21
					}`,
				},
			},
			CollectionCalls: map[string][]func(client.Collection) error{
				"users": []func(c client.Collection) error{
					func(c client.Collection) error {
						ctx := context.Background()
						_, err := c.UpdateWithFilter(ctx, filter, `{
							"Name": "Eric"
						}`)
						if err != nil {
							return err
						}

						d, err := c.Get(ctx, doc.Key())
						if err != nil {
							return err
						}

						name, err := d.Get("Name")
						if err != nil {
							return err
						}

						assert.Equal(t, "Eric", name)

						return nil
					},
				},
			},
		},
	}

	for _, test := range tests {
		executeTestCase(t, test)
	}
}
