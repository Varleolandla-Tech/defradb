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
	"encoding/json"

	"github.com/sourcenetwork/defradb/version"
	"github.com/spf13/cobra"
)

var format string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version number of DefraDB and its components",
	RunE: func(cmd *cobra.Command, _ []string) error {
		dv, err := version.NewDefraVersion()
		if err != nil {
			return err
		}
		switch format {
		case "json":
			var buf bytes.Buffer
			dvj, err := json.Marshal(dv)
			if err != nil {
				return err
			}
			err = json.Indent(&buf, dvj, "", "    ")
			if err != nil {
				return err
			}
			cmd.Println(buf.String())
		default:
			cmd.Println(dv.String())
		}
		return nil
	},
}

func init() {
	versionCmd.Flags().StringVarP(&format, "format", "f", "", "version format. Options are text, json")
	rootCmd.AddCommand(versionCmd)
}
