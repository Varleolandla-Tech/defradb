// Copyright 2022 Democratized Data Foundation
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
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	httpapi "github.com/sourcenetwork/defradb/api/http"
	"github.com/sourcenetwork/defradb/logging"
	"github.com/spf13/cobra"
)

var (
	schemaFile string
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new schema type to a DefraDB instance",
	Long: `Example Usage:
> defradb client schema add -f user.sdl`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		var schema []byte
		if len(args) > 0 {
			schema = []byte(strings.Join(args, "\n"))
		} else if schemaFile != "" {
			buf, err := os.ReadFile(schemaFile)
			cobra.CheckErr(err)
			schema = buf
		} else {
			log.Fatal(ctx, "Missing schema")
		}

		endpoint, err := httpapi.JoinPaths(cfg.API.AddressToURL(), httpapi.SchemaLoadPath)
		if err != nil {
			log.ErrorE(ctx, "Join paths failed", err)
			return
		}

		res, err := http.Post(endpoint.String(), "text", bytes.NewBuffer(schema))
		cobra.CheckErr(err)

		defer func() {
			err = res.Body.Close()
			if err != nil {
				log.ErrorE(ctx, "Response body closing failed", err)
			}
		}()

		result, err := io.ReadAll(res.Body)
		cobra.CheckErr(err)
		log.Info(ctx, "", logging.NewKV("Result", string(result)))
	},
}

func init() {
	schemaCmd.AddCommand(addCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// addCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	addCmd.Flags().StringVarP(&schemaFile, "file", "f", "", "File to load a schema from")
}
