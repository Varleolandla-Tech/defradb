## defradb client rpc replicator set

Set a P2P replicator

### Synopsis

Add a new target replicator.
A replicator replicates one or all collection(s) from this node to another.


```
defradb client rpc replicator set [-f, --full | -c, --collection] <peer> [flags]
```

### Options

```
  -c, --collection stringArray   Define the collection for the replicator
  -f, --full                     Set the replicator to act on all collections
  -h, --help                     help for set
```

### Options inherited from parent commands

```
      --addr string          RPC endpoint address (default "0.0.0.0:9161")
      --logformat string     Log format to use. Options are csv, json (default "csv")
      --logger stringArray   Override logger parameters. Usage: --logger <name>,level=<level>,output=<output>,...
      --loglevel string      Log level to use. Options are debug, info, error, fatal (default "info")
      --lognocolor           Disable colored log output
      --logoutput string     Log output path (default "stderr")
      --logtrace             Include stacktrace in error and fatal logs
      --rootdir string       Directory for data and configuration to use (default: $HOME/.defradb)
      --url string           URL of HTTP endpoint to listen on or connect to (default "localhost:9181")
```

### SEE ALSO

* [defradb client rpc replicator](defradb_client_rpc_replicator.md)	 - Configure the replicator system

