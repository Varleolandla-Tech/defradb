// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package cli

import (
	"context"
	"encoding/json"

	"github.com/sourcenetwork/immutable/enumerable"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/datastore"
)

var _ client.LensRegistry = (*LensRegistry)(nil)

type LensRegistry struct {
	cmd *cliWrapper
}

func (w *LensRegistry) WithTxn(tx datastore.Txn) client.LensRegistry {
	return &LensRegistry{w.cmd.withTxn(tx)}
}

func (w *LensRegistry) SetMigration(ctx context.Context, config client.LensConfig) error {
	args := []string{"client", "schema", "migration", "set"}
	args = append(args, config.SourceSchemaVersionID)
	args = append(args, config.DestinationSchemaVersionID)

	lensCfg, err := json.Marshal(config.Lens)
	if err != nil {
		return err
	}
	args = append(args, string(lensCfg))

	_, err = w.cmd.execute(ctx, args)
	return err
}

func (w *LensRegistry) ReloadLenses(ctx context.Context) error {
	args := []string{"client", "schema", "migration", "reload"}

	_, err := w.cmd.execute(ctx, args)
	return err
}

func (w *LensRegistry) MigrateUp(
	ctx context.Context,
	src enumerable.Enumerable[map[string]any],
	schemaVersionID string,
) (enumerable.Enumerable[map[string]any], error) {
	args := []string{"client", "schema", "migration", "up"}
	args = append(args, "--version", schemaVersionID)

	var srcData []map[string]any
	err := enumerable.ForEach(src, func(item map[string]any) {
		srcData = append(srcData, item)
	})
	if err != nil {
		return nil, err
	}
	srcJSON, err := json.Marshal(srcData)
	if err != nil {
		return nil, err
	}
	args = append(args, string(srcJSON))

	data, err := w.cmd.execute(ctx, args)
	if err != nil {
		return nil, err
	}
	var out enumerable.Enumerable[map[string]any]
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (w *LensRegistry) MigrateDown(
	ctx context.Context,
	src enumerable.Enumerable[map[string]any],
	schemaVersionID string,
) (enumerable.Enumerable[map[string]any], error) {
	args := []string{"client", "schema", "migration", "down"}
	args = append(args, "--version", schemaVersionID)

	var srcData []map[string]any
	err := enumerable.ForEach(src, func(item map[string]any) {
		srcData = append(srcData, item)
	})
	if err != nil {
		return nil, err
	}
	srcJSON, err := json.Marshal(srcData)
	if err != nil {
		return nil, err
	}
	args = append(args, string(srcJSON))

	data, err := w.cmd.execute(ctx, args)
	if err != nil {
		return nil, err
	}
	var out enumerable.Enumerable[map[string]any]
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (w *LensRegistry) Config(ctx context.Context) ([]client.LensConfig, error) {
	args := []string{"client", "schema", "migration", "get"}

	data, err := w.cmd.execute(ctx, args)
	if err != nil {
		return nil, err
	}
	var cfgs []client.LensConfig
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return nil, err
	}
	return cfgs, nil
}

func (w *LensRegistry) HasMigration(ctx context.Context, schemaVersionID string) (bool, error) {
	cfgs, err := w.Config(ctx)
	if err != nil {
		return false, err
	}
	found := false
	for _, cfg := range cfgs {
		if cfg.SourceSchemaVersionID == schemaVersionID {
			found = true
		}
	}
	return found, nil
}
