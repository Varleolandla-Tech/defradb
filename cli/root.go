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

	"github.com/sourcenetwork/defradb/config"
	"github.com/sourcenetwork/defradb/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const badgerDatastoreName = "badger"

var (
	log          = logging.MustNewLogger("defra.cli")
	cfg          = config.DefaultConfig()
	rootDirParam string
)

var RootCmd = rootCmd

func Execute() {
	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		log.FeedbackError(ctx, fmt.Sprintf("%s", err))
	}
}

var rootCmd = &cobra.Command{
	Use:   "defradb",
	Short: "DefraDB Edge Database",
	Long: `DefraDB is the edge database to power the user-centric future.
This CLI is the main reference implementation of DefraDB. Use it to start
a new database process, query a local or remote instance, and much more.

For example:

# Start a new database instance
> defradb start `,
	// Runs on subcommands before their Run function, to handle configuration and top-level flags.
	// Loads the rootDir containing the configuration file, otherwise warn about it and load a default configuration.
	// This allows some subcommands (`init`, `start`) to override the PreRun to create a rootDir by default.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		rootDir, exists, err := config.GetRootDir(rootDirParam)
		if err != nil {
			log.FatalE(ctx, "Could not get rootdir", err)
		}
		if exists {
			err := cfg.Load(rootDir)
			if err != nil {
				log.FatalE(ctx, "Could not load config file", err)
			}
			loggingConfig, err := cfg.GetLoggingConfig()
			if err != nil {
				log.FatalE(ctx, "Could not get logging config", err)
			}
			logging.SetConfig(loggingConfig)
			log.Debug(ctx, fmt.Sprintf("Configuration loaded from DefraDB directory %v", rootDir))
		} else {
			err := cfg.LoadWithoutRootDir()
			if err != nil {
				log.FatalE(ctx, "Could not load config file", err)
			}
			loggingConfig, err := cfg.GetLoggingConfig()
			if err != nil {
				log.FatalE(ctx, "Could not get logging config", err)
			}
			logging.SetConfig(loggingConfig)
			log.Info(ctx, "Using default configuration. To create DefraDB's directory, use defradb init.")
		}
	},
}

func init() {
	var err error

	rootCmd.PersistentFlags().StringVar(
		&rootDirParam, "rootdir", "",
		"directory for data and configuration to use (default \"$HOME/.defradb\")",
	)

	rootCmd.PersistentFlags().String(
		"loglevel", cfg.Log.Level,
		"log level to use. Options are debug, info, error, fatal",
	)
	err = viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("loglevel"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind log.loglevel", err)
	}

	rootCmd.PersistentFlags().String(
		"logoutput", cfg.Log.OutputPath,
		"log output path",
	)
	err = viper.BindPFlag("log.outputpath", rootCmd.PersistentFlags().Lookup("logoutput"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind log.outputpath", err)
	}

	rootCmd.PersistentFlags().String(
		"logformat", cfg.Log.Format,
		"log format to use. Options are text, json",
	)
	err = viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("logformat"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind log.format", err)
	}

	rootCmd.PersistentFlags().Bool(
		"logtrace", cfg.Log.Stacktrace,
		"include stacktrace in error and fatal logs",
	)
	err = viper.BindPFlag("log.stacktrace", rootCmd.PersistentFlags().Lookup("logtrace"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind log.stacktrace", err)
	}

	rootCmd.PersistentFlags().Bool(
		"logcolor", cfg.Log.Color,
		"enable colored output",
	)
	err = viper.BindPFlag("log.color", rootCmd.PersistentFlags().Lookup("logcolor"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind log.color", err)
	}

	rootCmd.PersistentFlags().String(
		"url", cfg.API.Address,
		"URL of the target database's HTTP endpoint",
	)
	err = viper.BindPFlag("api.address", rootCmd.PersistentFlags().Lookup("url"))
	if err != nil {
		log.FatalE(context.Background(), "Could not bind api.address", err)
	}
	rootCmd.SilenceErrors = true
}
