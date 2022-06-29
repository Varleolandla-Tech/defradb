// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package config

import (
	"os"
	"path/filepath"
)

// DefaultRootDir returns the default rootdir path, which is at the user's home directory.
func DefaultRootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultDefraDBRootDir), nil
}

// GetRootDir returns rootdir path and whether it exists as directory, considering the env. variable and CLI flag.
func GetRootDir(rootDir string) (string, bool, error) {
	var err error
	var path string
	rootDirEnv := os.Getenv(DefraEnvPrefix + "_ROOT")
	if rootDirEnv == "" && rootDir == "" {
		path, err = DefaultRootDir()
		if err != nil {
			return "", false, err
		}
	} else if rootDirEnv != "" && rootDir == "" {
		path = rootDirEnv
	} else {
		path = rootDir
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	info, err := os.Stat(path)
	exists := (err == nil && info.IsDir())
	return path, exists, nil
}

// CreateRootDirWithDefaultConfig creates a rootdir with default configuration.
func CreateRootDirWithDefaultConfig(rootDir string) error {
	err := os.MkdirAll(rootDir, defaultDirPerm)
	if err != nil {
		return err
	}
	cfg := DefaultConfig()
	err = cfg.WriteConfigFileToRootDir(rootDir)
	if err != nil {
		return err
	}
	return nil
}
