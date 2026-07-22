Before sending a PR:

- `go test ./... -race -count=1` passes
- `golangci-lint run ./...` is clean
- CHANGELOG.md entry added

Code style:
- return errors, don't panic
- use context for I/O
- no magic values, use constants
- stdlib over external deps

Open an issue if something's broken.
