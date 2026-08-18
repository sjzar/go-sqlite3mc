# Contributing

Thanks for helping improve `go-sqlite3mc`.

Before opening a pull request, run:

```sh
gofmt -w .
go test ./...
go vet ./...
```

Keep changes focused, include tests for behavior changes, and do not include
database files, encryption keys, generated binaries, or private customer data.
Changes to the bundled C amalgamation should be reproducible from the
corresponding upstream release and retain its original notices.
