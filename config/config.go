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

`Config` embeds component-specific config structs. Each config struct can have a function providing
default options, a method providing test configurations, a method for validation, a method handling deprecated fields
(e.g. with warnings). This is extensible.

The 'root directory' is where the configuration file and data of a DefraDB instance exists. It is specified as a global
flag `defradb --rootdir path/to/somewhere`, or with the DEFRA_ROOT environment variable.

Some packages of DefraDB provide their own configuration approach (logging, node). For each, a way to go from top-level
configuration to package-specific configuration is provided.

Parameters are determined by, in order of least importance: defaults, configuration file, env. variables, and then CLI
flags. That is, CLI flags can override everything else.

For example `DEFRA_DATASTORE_BADGER_PATH` matches `Config.Datastore.Badger.Path` and in the config file:

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
	defaultDefraDBConfigFileName = "config.yaml"
	defaultDefraDBRootDir        = ".defradb"
	defraEnvPrefix               = "DEFRA"
)

type Config struct {
	Datastore *DatastoreConfig
	API       *APIConfig
	Net       *NetConfig
	Logging   *LoggingConfig
}

// Load into Config and handles parameters from config file, environment variables, and CLI flags.
// To use on a Config struct already loaded with default values from DefaultConfig().
func (cfg *Config) Load(rootDirPath string) error {
	var err error

	viper.SetConfigName(defaultDefraDBConfigFileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(rootDirPath)
	if err = viper.ReadInConfig(); err != nil {
		return err
	}

	viper.SetEnvPrefix(defraEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	err = cfg.validateBasic()
	if err != nil {
		return err
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	cfg.handleParams(rootDirPath)
	return nil
}

// Load into Config and handles parameters from defaults, environment variables, and CLI flags - not from config file.
// To use on a Config struct already loaded with default values from DefaultConfig().
func (cfg *Config) LoadWithoutRootDir() error {
	var err error
	// With Viper, we use a config file to provide a basic structure and set defaults, for env. variables to load.
	viper.SetConfigType("yaml")
	configbytes, err := cfg.toBytes()
	if err != nil {
		return err
	}
	err = viper.ReadConfig(bytes.NewReader(configbytes))
	if err != nil {
		return err
	}

	viper.SetEnvPrefix(defraEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	err = cfg.validateBasic()
	if err != nil {
		return err
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	cfg.handleParams(DefaultRootDir())
	return nil
}

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
		return fmt.Errorf("Failed to validate Datastore config: %v", err)
	}
	if err := cfg.API.validateBasic(); err != nil {
		return fmt.Errorf("Failed to validate API config: %v", err)
	}
	if err := cfg.Net.validateBasic(); err != nil {
		return fmt.Errorf("Failed to validate Net config: %v", err)
	}
	if err := cfg.Logging.validateBasic(); err != nil {
		return fmt.Errorf("Failed to validate Logging config: %v", err)
	}
	return nil
}

func (cfg *Config) handleParams(rootDir string) {
	// We prefer using absolute paths.
	if !filepath.IsAbs(cfg.Datastore.Badger.Path) {
		cfg.Datastore.Badger.Path = filepath.Join(rootDir, cfg.Datastore.Badger.Path)
	}
}

// func (cfg *Config) deprecatedFieldWarning() {
// 	panic("placeholder for future configuration deprecation")
// }

// DatastoreConfig configures datastores.
type DatastoreConfig struct {
	Store  string
	Memory MemoryConfig
	Badger BadgerConfig
}

type BadgerConfig struct {
	Path string
	*badgerds.Options
}

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
		return fmt.Errorf("Invalid store type: %s", dbcfg.Store)
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
		return fmt.Errorf("No database URL provided")
	}
	_, err := net.ResolveTCPAddr("tcp", apicfg.Address)
	if err != nil {
		return fmt.Errorf("Invalid database URL: %v", err)
	}
	return nil
}

func (apicfg *APIConfig) AddressToURL() string {
	return fmt.Sprintf("http://%s", apicfg.Address)
}

// NetConfig configures aspects of network and peer-to-peer.
type NetConfig struct {
	P2PAddress           string
	P2PDisabled          bool
	TCPAddress           string
	RPCTimeout           string
	RPCAddress           string
	PubSubEnabled        bool `mapstructure:"pubsub"`
	RelayEnabled         bool `mapstructure:"relay"`
	RPCMaxConnectionIdle string
	Peers                string
}

func defaultNetConfig() *NetConfig {
	return &NetConfig{
		P2PAddress:           "/ip4/0.0.0.0/tcp/9171",
		TCPAddress:           "/ip4/0.0.0.0/tcp/9161",
		RPCAddress:           "0.0.0.0:9161",
		RPCTimeout:           "10s",
		P2PDisabled:          false,
		RPCMaxConnectionIdle: "5m",
		Peers:                "",
	}
}

func (netcfg *NetConfig) validateBasic() error {
	_, err := time.ParseDuration(netcfg.RPCTimeout)
	if err != nil {
		return fmt.Errorf("Invalid RPC timeout: %s", netcfg.RPCTimeout)
	}
	_, err = time.ParseDuration(netcfg.RPCMaxConnectionIdle)
	if err != nil {
		return fmt.Errorf("Invalid RPC MaxConnectionIdle: %s", netcfg.RPCMaxConnectionIdle)
	}
	if len(netcfg.Peers) > 0 {
		peers := strings.Split(netcfg.Peers, ",")
		maddrs := make([]ma.Multiaddr, len(peers))
		for i, addr := range peers {
			maddrs[i], err = ma.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("Failed to parse bootstrap peers: %s", netcfg.Peers)
			}
		}
	}
	return nil
}

func (netcfg *NetConfig) RPCTimeoutDuration() (time.Duration, error) {
	d, err := time.ParseDuration(netcfg.RPCTimeout)
	if err != nil {
		return d, err
	}
	return d, nil
}

func (netcfg *NetConfig) RPCMaxConnectionIdleDuration() (time.Duration, error) {
	d, err := time.ParseDuration(netcfg.RPCMaxConnectionIdle)
	if err != nil {
		return d, err
	}
	return d, nil
}

// From top-level Net config to Node-specific configuration
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
		opt.ConnManager = node.NewConnManager(100, 400, time.Second*20)
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
		OutputPath: "stdout",
		Color:      true,
	}
}

func (logcfg *LoggingConfig) validateBasic() error {
	return nil
}

// From top-level config to logging-specific configuration
func (cfg *Config) GetLoggingConfig() (logging.Config, error) {
	var loglvl logging.LogLevel
	switch cfg.Logging.Level {
	case "debug":
		loglvl = logging.Debug
	case "info":
		loglvl = logging.Info
	case "warn":
		loglvl = logging.Warn
	case "error":
		loglvl = logging.Error
	case "fatal":
		loglvl = logging.Fatal
	default:
		return logging.Config{}, fmt.Errorf("Invalid log level: %s", cfg.Logging.Level)
	}
	var encfmt logging.EncoderFormat
	switch cfg.Logging.Format {
	case "json":
		encfmt = logging.JSON
	case "csv":
		encfmt = logging.CSV
	default:
		return logging.Config{}, fmt.Errorf("Invalid log format: %s", cfg.Logging.Format)
	}
	return logging.Config{
		Level:            logging.NewLogLevelOption(loglvl),
		EnableStackTrace: logging.NewEnableStackTraceOption(cfg.Logging.Stacktrace),
		EncoderFormat:    logging.NewEncoderFormatOption(encfmt),
		OutputPaths:      []string{cfg.Logging.OutputPath},
		// OverridesByLoggerName: map[string]OverrideConfig
	}, nil
}

func (c *Config) ToJSON() ([]byte, error) {
	jsonbytes, err := json.Marshal(c)
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to marshal Config to JSON: %s", err)
	}
	return jsonbytes, nil
}

func (c *Config) toBytes() ([]byte, error) {
	var buffer bytes.Buffer
	tmpl := template.New("configTemplate")
	configTemplate, err := tmpl.Parse(defaultConfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("could not parse config template: %v", err)
	}
	if err := configTemplate.Execute(&buffer, c); err != nil {
		return nil, fmt.Errorf("could not execute config template: %v", err)
	}
	return buffer.Bytes(), nil
}
