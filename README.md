# go-sqlite3mc

[![Go Reference](https://pkg.go.dev/badge/github.com/sjzar/go-sqlite3mc.svg)](https://pkg.go.dev/github.com/sjzar/go-sqlite3mc)
[![CI](https://github.com/sjzar/go-sqlite3mc/actions/workflows/ci.yml/badge.svg)](https://github.com/sjzar/go-sqlite3mc/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sjzar/go-sqlite3mc)](https://goreportcard.com/report/github.com/sjzar/go-sqlite3mc)

`sqlite3mc` is a small Go wrapper around [SQLite3 Multiple Ciphers](https://utelle.github.io/SQLite3MultipleCiphers/), providing access to AES-128-CBC encrypted SQLite databases through cgo.

## Requirements

- Go 1.22 or newer
- cgo enabled (`CGO_ENABLED=1`)
- A C compiler supported by Go (for example, clang or gcc)

The package currently targets Linux and macOS. The SQLite and SQLite3 Multiple Ciphers amalgamations are included in this repository, so consumers do not need a system SQLite installation.

## Install

```sh
go get github.com/sjzar/go-sqlite3mc@latest
```

## Usage

The key must be the 16-byte raw database key represented as exactly 32 hexadecimal characters. `Open` opens an existing database read-only; use `OpenReadWrite` when creating or maintaining a database.

```go
package main

import (
	"context"
	"log"

	"github.com/sjzar/go-sqlite3mc"
)

func main() {
	db, err := sqlite3mc.Open("Info.db", "0123456789abcdef0123456789abcdef")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(context.Background(), "SELECT name FROM sqlite_master WHERE type = ?", "table")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tables: %v", rows)
}
```

`DB` serializes operations so one handle can safely be shared by goroutines. `Query` checks the context between rows; cancellation cannot interrupt a single SQLite C call already in progress.

## Security and compatibility

This package is intended for reading databases encrypted with the AES-128-CBC configuration used by SQLite3 Multiple Ciphers. It does not manage keys, rotate keys, or provide a general-purpose SQL security layer. Never commit database files or keys to source control.

The bundled C sources are third-party components. Their upstream copyright and license notices are retained in the source files; see [NOTICE](NOTICE) for the attribution summary.

## Development

```sh
go test ./...
go vet ./...
```

To run the optional live-database check:

```sh
SQLITE3MC_TEST_DB=/path/to/database.db \
SQLITE3MC_TEST_KEY=0123456789abcdef0123456789abcdef \
go test -run TestOpenLiveEncryptedDatabase
```

## License

The Go wrapper is licensed under the Apache License 2.0. See [LICENSE](LICENSE). The bundled SQLite3 Multiple Ciphers and SQLite sources retain their respective upstream notices.
