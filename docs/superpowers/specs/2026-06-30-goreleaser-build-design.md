# GoReleaser build (issue #5)

**Author:** Paul Snow
**Date:** 2026-06-30
**Status:** Approved

## Goal

Automate cross-platform binary builds and releases for the `wg-dns-sync`
Go CLI using [GoReleaser](https://goreleaser.com) (v2 config schema, tested
against goreleaser 2.14). A `git tag v*` push produces a GitHub Release with
archives, checksums, Linux packages, and a Homebrew formula.

## Scope

- Cross-platform build: `linux`, `darwin`, `windows` on `amd64` + `arm64`
  (Windows/arm64 excluded).
- Artifacts: archives + checksums, `.deb`/`.rpm` packages, Homebrew tap formula.
- A runtime `version` command exposing the injected build metadata.
- A tag-triggered GitHub Actions release workflow.

Out of scope: signing/notarisation, Docker images, Snap/Scoop, changelog
automation beyond GoReleaser's built-in grouping.

## Design

### 1. Version injection (CLI change)

`main.go` stays thin. Build metadata lives in `internal/app` as package-level
vars so the values are testable and `main.go` is unchanged:

```go
// internal/app/version.go
var (
    Version = "dev"
    Commit  = "none"
    Date    = "unknown"
)
```

- The root command sets `cmd.Version` from `Version`, enabling `--version`.
- A `version` subcommand (mirrors the existing `completion` subcommand) prints
  `version`, `commit`, `date`, and the Go runtime version.
- GoReleaser injects the vars via ldflags targeting the `internal/app` package:
  `-s -w -X github.com/bovinemagnet/wg-dns-sync/internal/app.Version={{.Version}}`
  (and `.Commit`, `.Date`).

### 2. `.goreleaser.yaml` (schema `version: 2`)

- `builds`: single build of `./cmd/wg-dns-sync`, `CGO_ENABLED=0`,
  `goos: [linux, darwin, windows]`, `goarch: [amd64, arm64]`,
  `ignore` windows/arm64, ldflags as above.
- `archives`: `tar.gz` (unix) / `zip` (windows); include `README.adoc`.
  LICENSE is intentionally **not** listed (none exists yet — added later).
- `checksum`: `checksums.txt`, sha256.
- `nfpms`: `formats: [deb, rpm]`, maintainer `Paul Snow`,
  description/homepage from the repo.
- `brews`: formula pushed to `bovinemagnet/homebrew-tap`. The `license` field
  is omitted until a LICENSE file is added.
- `snapshot` name template and `changelog` grouping (filter docs/test/chore
  commits).

### 3. Release workflow

`.github/workflows/release.yml`:

- Trigger: `push: tags: ['v*']`.
- `permissions: contents: write`.
- Steps: checkout (full history), `setup-go`, `goreleaser/goreleaser-action@v6`
  running `release --clean`.
- Env: `GITHUB_TOKEN` for the release; `HOMEBREW_TAP_GITHUB_TOKEN` (PAT with
  write access to the tap repo) for the Homebrew formula push.

### 4. External setup (manual, documented — not done here)

- Repo `bovinemagnet/homebrew-tap` must exist.
- Repo secret `HOMEBREW_TAP_GITHUB_TOKEN` (PAT, write to the tap repo).
- A `LICENSE` file (to be added later); once present, add it to archive `files`
  and set the brew `license` field.

## Testing / verification

- TDD: table test for the `version` subcommand asserting its output contains the
  (overridden) `Version`/`Commit`/`Date` package vars.
- `goreleaser check` validates the config.
- `goreleaser release --snapshot --clean` builds all artifacts locally.
- Existing `go vet ./...` / `go test ./...` continue to pass.
