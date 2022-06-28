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
	"context"
	"fmt"
	"io"
	"net/http"

	httpapi "github.com/sourcenetwork/defradb/api/http"
	"github.com/spf13/cobra"
)

// dumpCmd represents the dump command
var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dumps the state of the entire database (server side)",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		endpoint, err := httpapi.JoinPaths(cfg.API.AddressToURL(), httpapi.DumpPath)
		if err != nil {
			log.ErrorE(ctx, "Join paths failed", err)
			return
		}

		res, err := http.Get(endpoint.String())
		if err != nil {
			log.ErrorE(ctx, "Request failed", err)
			return
		}

		defer func() {
			err = res.Body.Close()
			if err != nil {
				log.ErrorE(ctx, "Response body closing failed", err)
			}
		}()

		buf, err := io.ReadAll(res.Body)
		if err != nil {
			log.ErrorE(ctx, "Request failed", err)
			return
		}
		if string(buf) == "ok" {
			log.Info(ctx, "Success!")
		} else {
			log.ErrorE(ctx, "Unexpected result: ", fmt.Errorf(string(buf)))
		}
	},
}

func init() {
	clientCmd.AddCommand(dumpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dumpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dumpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
