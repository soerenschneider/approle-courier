package registry

import (
	"context"
	"encoding/json"
)

// KVReader reads KV v2 secrets. *vault.Client implements it.
type KVReader interface {
	ReadKV2(ctx context.Context, mount, path string) (json.RawMessage, error)
}

// KVSource loads the registry document from a single Vault KV v2 secret
// whose data is the document.
//
// Each key of the secret is a machine ID; its value holds the machine's age
// recipient and the roles it may request, keyed by AppRole mount:
//
//	{
//	  "node-42": {
//	    "age_recipient": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
//	    "roles": {"approle": ["my-role"]}
//	  },
//	  "db-01.example.com": {
//	    "age_recipient": "age1...",
//	    "roles": {"approle": ["db"], "approle-infra": ["backup"]}
//	  }
//	}
//
// so "bao kv get" lists one row per machine.
//
// Write it with the document as the secret's data, replacing the previous
// version as a whole so removed machines disappear:
//
//	bao kv put -mount=secret approle-courier/registry @registry.json
//
// or through the HTTP API, where KV v2 nests the document under "data":
//
//	POST /v1/secret/data/approle-courier/registry
//	{"data": {"node-42": {...}, ...}}
//
// Reads return it under data.data, next to the version metadata:
//
//	GET /v1/secret/data/approle-courier/registry
//	{"data": {"data": {"node-42": {...}, ...}, "metadata": {"version": 3, ...}}}
//
// The service's Vault token needs "read" on <mount>/data/<path>; nothing the
// issued AppRole tokens can reach should be able to write it.
type KVSource struct {
	Reader KVReader
	Mount  string
	Path   string
}

func (k KVSource) Load(ctx context.Context) ([]byte, error) {
	return k.Reader.ReadKV2(ctx, k.Mount, k.Path)
}

func (k KVSource) String() string { return "kv " + k.Mount + "/" + k.Path }
