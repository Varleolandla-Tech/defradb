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

	"github.com/spf13/cobra"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/config"
	"github.com/sourcenetwork/defradb/datastore"
)

func MakeCollectionCommand(cfg *config.Config) *cobra.Command {
	var txID uint64
	var name string
	var schemaID string
	var versionID string
	var cmd = &cobra.Command{
		Use:   "collection [--name <name> --schema <schemaID> --version <versionID>]",
		Short: "Interact with a collection.",
		Long:  `Create, read, update, and delete documents within a collection.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) (err error) {
			// cobra does not chain pre run calls so we have to run them again here
			if err := loadConfig(cfg); err != nil {
				return err
			}
			if err := setTransactionContext(cmd, cfg, txID); err != nil {
				return err
			}
			if err := setStoreContext(cmd, cfg); err != nil {
				return err
			}
			store := mustGetStoreContext(cmd)

			var col client.Collection
			switch {
			case versionID != "":
				col, err = store.GetCollectionByVersionID(cmd.Context(), versionID)

			case schemaID != "":
				col, err = store.GetCollectionBySchemaID(cmd.Context(), schemaID)

			case name != "":
				col, err = store.GetCollectionByName(cmd.Context(), name)

			default:
				return nil
			}

			if err != nil {
				return err
			}
			if tx, ok := cmd.Context().Value(txContextKey).(datastore.Txn); ok {
				col = col.WithTxn(tx)
			}

			ctx := context.WithValue(cmd.Context(), colContextKey, col)
			cmd.SetContext(ctx)
			return nil
		},
	}
	cmd.PersistentFlags().Uint64Var(&txID, "tx", 0, "Transaction ID")
	cmd.PersistentFlags().StringVar(&name, "name", "", "Collection name")
	cmd.PersistentFlags().StringVar(&schemaID, "schema", "", "Collection schema ID")
	cmd.PersistentFlags().StringVar(&versionID, "version", "", "Collection version ID")
	return cmd
}
