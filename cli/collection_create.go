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
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/internal/db"
)

func MakeCollectionCreateCommand() *cobra.Command {
	var file string
	var shouldEncrypt bool
	var cmd = &cobra.Command{
		Use:   "create [-i --identity] [-e --encrypt] <document>",
		Short: "Create a new document.",
		Long: `Create a new document.
		
Options:
    -i, --identity 
        Marks the document as private and set the identity as the owner. The access to the document
		and permissions are controlled by ACP (Access Control Policy).

	-e, --encrypt
		Encrypt flag specified if the document needs to be encrypted. If set, DefraDB will generate a
		symmetric key for encryption using AES-GCM.

Example: create from string:
  defradb client collection create --name User '{ "name": "Bob" }'

Example: create from string, with identity:
  defradb client collection create --name User '{ "name": "Bob" }' \
  	-i 028d53f37a19afb9a0dbc5b4be30c65731479ee8cfa0c9bc8f8bf198cc3c075f

Example: create multiple from string:
  defradb client collection create --name User '[{ "name": "Alice" }, { "name": "Bob" }]'

Example: create from file:
  defradb client collection create --name User -f document.json

Example: create from stdin:
  cat document.json | defradb client collection create --name User -
		`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var docData []byte
			switch {
			case file != "":
				data, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				docData = data
			case len(args) == 1 && args[0] == "-":
				data, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
				docData = data
			case len(args) == 1:
				docData = []byte(args[0])
			default:
				return ErrNoDocOrFile
			}

			col, ok := tryGetContextCollection(cmd)
			if !ok {
				return cmd.Usage()
			}

			txn, _ := db.TryGetContextTxn(cmd.Context())
			setContextDocEncryption(cmd, shouldEncrypt, txn)

			if client.IsJSONArray(docData) {
				docs, err := client.NewDocsFromJSON(docData, col.Definition())
				if err != nil {
					return err
				}
				return col.CreateMany(cmd.Context(), docs)
			}

			doc, err := client.NewDocFromJSON(docData, col.Definition())
			if err != nil {
				return err
			}
			return col.Create(cmd.Context(), doc)
		},
	}
	cmd.PersistentFlags().BoolVarP(&shouldEncrypt, "encrypt", "e", false,
		"Flag to enable encryption of the document")
	cmd.Flags().StringVarP(&file, "file", "f", "", "File containing document(s)")
	return cmd
}
