// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

/*
Package config provides the central point for DefraDB's configuration and related facilities.

[Config] embeds component-specific config structs. Each config struct can have a function providing
default options, a method providing test configurations, a method for validation, a method handling deprecated fields
(e.g. with warnings). This is extensible.

The 'root directory' is where the configuration file and data of a DefraDB instance exists. It is specified as a global
flag `defradb --rootdir path/to/somewhere`, or with the DEFRA_ROOT environment variable.

Some packages of DefraDB provide their own configuration approach (logging, node). For each, a way to go from top-level
configuration to package-specific configuration is provided.

Parameters are determined by, in order of least importance: defaults, configuration file, env. variables, and then CLI
flags. That is, CLI flags can override everything else.

For example `DEFRA_DATASTORE_BADGER_PATH` matches [Config.Datastore.Badger.Path] and in the config file:

	datastore:
		badger:
			path: /tmp/badger

This implementation does not support online modification of configuration.

How to use, e.g. without using a rootdir:

	cfg := config.DefaultConfig()
	cfg.NetConfig.P2PDisabled = true  // as example
	err := cfg.LoadWithoutRootDir()
	if err != nil {
		...

*/
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	badgerds "github.com/sourcenetwork/defradb/datastore/badger/v3"
	"github.com/sourcenetwork/defradb/logging"
	"github.com/sourcenetwork/defradb/node"
	"github.com/spf13/viper"
)

var log = logging.MustNewLogger("defra.config")

const (
	DefraEnvPrefix        = "DEFRA"
	defaultDefraDBRootDir = ".defradb"
)

// Config is DefraDB's main configuration struct, embedding component-specific config structs.
type Config struct {
	Datastore *DatastoreConfig
	API       *APIConfig
	Net       *NetConfig
	Logging   *LoggingConfig
}

// Load Config and handles parameters from config file, environment variables.
// To use on a Config struct already loaded with default values from DefaultConfig().
func (cfg *Config) Load(rootDirPath string) error {
	viper.SetConfigName(DefaultDefraDBConfigFileName)
	viper.SetConfigType(configType)
	viper.AddConfigPath(rootDirPath)
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	viper.SetEnvPrefix(DefraEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	cfg.handleParams(rootDirPath)
	err := cfg.validateBasic()
	if err != nil {
		return err
	}
	return nil
}

// LoadWithoutRootDir loads Config and handles parameters from defaults, environment variables, and CLI flags -
// not from config file.
// To use on a Config struct already loaded with default values from DefaultConfig().
func (cfg *Config) LoadWithoutRootDir() error {
	// With Viper, we use a config file to provide a basic structure and set defaults, for env. variables to load.
	viper.SetConfigType(configType)
	configbytes, err := cfg.toBytes()
	if err != nil {
		return err
	}
	err = viper.ReadConfig(bytes.NewReader(configbytes))
	if err != nil {
		return err
	}

	viper.SetEnvPrefix(DefraEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	rootDir, err := DefaultRootDir()
	if err != nil {
		log.FatalE(context.Background(), "Could not get home directory", err)
	}
	cfg.handleParams(rootDir)
	err = cfg.validateBasic()
	if err != nil {
		return err
	}
	return nil
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Datastore: defaultDatastoreConfig(),
		API:       defaultAPIConfig(),
		Net:       defaultNetConfig(),
		Logging:   defaultLoggingConfig(),
	}
}

func (cfg *Config) validateBasic() error {
	if err := cfg.Datastore.validateBasic(); err != nil {
		return fmt.Errorf("failed to validate Datastore config: %w", err)
	}
	if err := cfg.API.validateBasic(); err != nil {
		return fmt.Errorf("failed to validate API config: %w", err)
	}
	if err := cfg.Net.validateBasic(); err != nil {
		return fmt.Errorf("failed to validate Net config: %w", err)
	}
	if err := cfg.Logging.validateBasic(); err != nil {
		return fmt.Errorf("failed to validate Logging config: %w", err)
	}
	return nil
}

func (cfg *Config) handleParams(rootDir string) {
	// We prefer using absolute paths.
	if !filepath.IsAbs(cfg.Datastore.Badger.Path) {
		cfg.Datastore.Badger.Path = filepath.Join(rootDir, cfg.Datastore.Badger.Path)
	}
}

// DatastoreConfig configures datastores.
type DatastoreConfig struct {
	Store  string
	Memory MemoryConfig
	Badger BadgerConfig
}

// BadgerConfig configures Badger's on-disk / filesystem mode.
type BadgerConfig struct {
	Path string
	*badgerds.Options
}

// MemoryConfig configures of Badger's memory mode.
type MemoryConfig struct {
	Size uint64
}

func defaultDatastoreConfig() *DatastoreConfig {
	return &DatastoreConfig{
		Store: "badger",
		Badger: BadgerConfig{
			Path: "data",
		},
	}
}

func (dbcfg DatastoreConfig) validateBasic() error {
	switch dbcfg.Store {
	case "badger", "memory":
	default:
		return fmt.Errorf("invalid store type: %s", dbcfg.Store)
	}
	return nil
}

// APIConfig configures the API endpoints.
type APIConfig struct {
	Address string
}

func defaultAPIConfig() *APIConfig {
	return &APIConfig{
		Address: "localhost:9181",
	}
}

func (apicfg *APIConfig) validateBasic() error {
	if apicfg.Address == "" {
		return fmt.Errorf("no database URL provided")
	}
	_, err := net.ResolveTCPAddr("tcp", apicfg.Address)
	if err != nil {
		return fmt.Errorf("invalid database URL: %w", err)
	}
	return nil
}

// AddressToURL provides the API address as URL.
func (apicfg *APIConfig) AddressToURL() string {
	return fmt.Sprintf("http://%s", apicfg.Address)
}

// NetConfig configures aspects of network and peer-to-peer.
type NetConfig struct {
	P2PAddress           string
	P2PDisabled          bool
	Peers                string
	PubSubEnabled        bool `mapstructure:"pubsub"`
	RelayEnabled         bool `mapstructure:"relay"`
	RPCAddress           string
	RPCMaxConnectionIdle string
	RPCTimeout           string
	TCPAddress           string
}

func defaultNetConfig() *NetConfig {
	return &NetConfig{
		P2PAddress:           "/ip4/0.0.0.0/tcp/9171",
		P2PDisabled:          false,
		Peers:                "",
		PubSubEnabled:        true,
		RelayEnabled:         false,
		RPCAddress:           "0.0.0.0:9161",
		RPCMaxConnectionIdle: "5m",
		RPCTimeout:           "10s",
		TCPAddress:           "/ip4/0.0.0.0/tcp/9161",
	}
}

func (netcfg *NetConfig) validateBasic() error {
	_, err := time.ParseDuration(netcfg.RPCTimeout)
	if err != nil {
		return fmt.Errorf("invalid RPC timeout: %s", netcfg.RPCTimeout)
	}
	_, err = time.ParseDuration(netcfg.RPCMaxConnectionIdle)
	if err != nil {
		return fmt.Errorf("invalid RPC MaxConnectionIdle: %s", netcfg.RPCMaxConnectionIdle)
	}
	_, err = ma.NewMultiaddr(netcfg.P2PAddress)
	if err != nil {
		return fmt.Errorf("invalid P2P address: %s", netcfg.P2PAddress)
	}
	if len(netcfg.Peers) > 0 {
		peers := strings.Split(netcfg.Peers, ",")
		maddrs := make([]ma.Multiaddr, len(peers))
		for i, addr := range peers {
			maddrs[i], err = ma.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("failed to parse bootstrap peers: %s", netcfg.Peers)
			}
		}
	}
	return nil
}

// RPCTimeoutDuration gives the RPC timeout as a time.Duration.
func (netcfg *NetConfig) RPCTimeoutDuration() (time.Duration, error) {
	d, err := time.ParseDuration(netcfg.RPCTimeout)
	if err != nil {
		return d, err
	}
	return d, nil
}

// RPCMaxConnectionIdleDuration gives the RPC MaxConnectionIdle as a time.Duration.
func (netcfg *NetConfig) RPCMaxConnectionIdleDuration() (time.Duration, error) {
	d, err := time.ParseDuration(netcfg.RPCMaxConnectionIdle)
	if err != nil {
		return d, err
	}
	return d, nil
}

// NodeConfig provides the Node-specific configuration, from the top-level Net config.
func (cfg *Config) NodeConfig() node.NodeOpt {
	return func(opt *node.Options) error {
		var err error
		err = node.ListenP2PAddrStrings(cfg.Net.P2PAddress)(opt)
		if err != nil {
			return err
		}
		err = node.ListenTCPAddrString(cfg.Net.TCPAddress)(opt)
		if err != nil {
			return err
		}
		opt.EnableRelay = cfg.Net.RelayEnabled
		opt.EnablePubSub = cfg.Net.PubSubEnabled
		opt.DataPath = cfg.Datastore.Badger.Path
		opt.ConnManager, err = node.NewConnManager(100, 400, time.Second*20)
		if err != nil {
			return err
		}
		return nil
	}
}

// LoggingConfig configures output and logger.
type LoggingConfig struct {
	Level      string
	Stacktrace bool
	Format     string
	OutputPath string // logging actually supports multiple output paths, but here only one is supported
	Color      bool
}

func defaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:      "info",
		Stacktrace: false,
		Format:     "csv",
		OutputPath: "stderr",
		Color:      false,
	}
}

func (logcfg *LoggingConfig) validateBasic() error {
	return nil
}

// GetLoggingConfig provides logging-specific configuration, from top-level Config.
func (cfg *Config) GetLoggingConfig() (logging.Config, error) {
	var loglvl logging.LogLevel
	switch cfg.Logging.Level {
	case "debug":
		loglvl = logging.Debug
	case "info":
		loglvl = logging.Info
	case "error":
		loglvl = logging.Error
	case "fatal":
		loglvl = logging.Fatal
	default:
		return logging.Config{}, fmt.Errorf("invalid log level: %s", cfg.Logging.Level)
	}
	var encfmt logging.EncoderFormat
	switch cfg.Logging.Format {
	case "json":
		encfmt = logging.JSON
	case "csv":
		encfmt = logging.CSV
	default:
		return logging.Config{}, fmt.Errorf("invalid log format: %s", cfg.Logging.Format)
	}
	return logging.Config{
		Level:            logging.NewLogLevelOption(loglvl),
		EnableStackTrace: logging.NewEnableStackTraceOption(cfg.Logging.Stacktrace),
		EncoderFormat:    logging.NewEncoderFormatOption(encfmt),
		OutputPaths:      []string{cfg.Logging.OutputPath},
	}, nil
}

// ToJSON serializes the config to a JSON string.
func (c *Config) ToJSON() ([]byte, error) {
	jsonbytes, err := json.Marshal(c)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal Config to JSON: %w", err)
	}
	return jsonbytes, nil
}

func (c *Config) toBytes() ([]byte, error) {
	var buffer bytes.Buffer
	tmpl := template.New("configTemplate")
	configTemplate, err := tmpl.Parse(defaultConfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("could not parse config template: %w", err)
	}
	if err := configTemplate.Execute(&buffer, c); err != nil {
		return nil, fmt.Errorf("could not execute config template: %w", err)
	}
	return buffer.Bytes(), nil
}
