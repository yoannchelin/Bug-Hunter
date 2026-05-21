# Bug Hunter

**Bug Hunter** answers the question: *"where did it already bug, and will it bug again?"*

It is the 4th agent in the [Git Archaeologist](https://github.com/yoannchelin/Git-archeologist) ecosystem. It reads the SQLite database produced by Archaeologist and detects four classes of risk signals:

| Signal | What it detects |
|---|---|
| **Fix hotspot** | Files where >40% of commits are bugfixes, weighted by blast radius |
| **Silent error** | Go code patterns where errors are ignored, swallowed, or not propagated |
| **Bus factor 1** | Files owned by a single inactive author |
| **Implicit coupling** | File pairs that always change together in fix commits but have no call-graph edge |

Everything runs **locally**, **without an LLM at the core**, and **without paid APIs**.

---

## Requirements

- Go 1.21+
- A SQLite database produced by [Git Archaeologist](https://github.com/yoannchelin/Git-archeologist)

---

## Build

```bash
make build          # produces bin/hunter and bin/hunter-mcp
make install        # copies binaries to ~/.local/bin
make test           # runs all 39 unit tests
```

---

## Usage

### Scan a repository

```bash
hunter scan --db /path/to/.archaeo/index.db --repo /path/to/repo
```

The scan:
1. Reads all commits and file-commit associations from the Archaeologist DB
2. Classifies commits as bugfix or feature using keyword heuristics
3. Computes fix ratio, bus factor, and co-change pairs per file
4. Walks the Go source tree and detects silent error patterns (AST analysis)
5. Writes all findings back into the same DB under `hunter_*` tables

Options:

| Flag | Description |
|---|---|
| `--db` | Path to Archaeologist SQLite DB (required) |
| `--repo` | Path to repo root for AST analysis |
| `--no-ast` | Skip AST analysis (faster on large repos) |

### Show hotspot files

```bash
hunter hotspots --db /path/to/.archaeo/index.db --top 20
```

### Show findings

```bash
hunter findings --db /path/to/.archaeo/index.db
hunter findings --db ... --severity high
hunter findings --db ... --kind silent_error
hunter findings --db ... --kind fix_hotspot --top 10
```

Valid `--kind` values: `fix_hotspot`, `silent_error`, `bus_factor_1`, `implicit_coupling`

---

## MCP server

`hunter-mcp` exposes 4 tools over JSON-RPC 2.0 stdio, compatible with Claude Desktop and any MCP client.

```bash
hunter-mcp --db /path/to/.archaeo/index.db
```

### Claude Desktop configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bug-hunter": {
      "command": "/path/to/hunter-mcp",
      "args": ["--db", "/path/to/.archaeo/index.db"]
    }
  }
}
```

### Available tools

| Tool | Description |
|---|---|
| `hotspot_files` | Top files by fix ratio × blast radius |
| `silent_errors` | Go files with ignored or swallowed errors |
| `implicit_couplings` | File pairs that co-change without a call-graph edge |
| `bug_risk_for_change` | Given files or a unified diff, returns relevant bug history |

#### `bug_risk_for_change` examples

```json
{ "files": ["internal/store/store.go", "cmd/hunter/main.go"] }
```

```json
{ "diff": "--- a/internal/store/store.go\n+++ b/internal/store/store.go\n..." }
```

---

## How it integrates with the ecosystem

Bug Hunter reads from (never writes to) the tables produced by Archaeologist and Blast Radius:

```
commits, file_commits, files, symbols, edges   ← Git Archaeologist
blast_metrics                                   ← Blast Radius (optional)
```

It writes findings to `hunter_*` tables in the same DB.

---

## Silent error patterns detected

| Kind | Pattern |
|---|---|
| `ignored_error` | `_ = someCall()` — entire return value discarded |
| `swallowed_panic` | `recover()` as a bare statement with no result capture |
| `lost_error` | `if err != nil { return }` bare return, or `return nil, nil` without propagating err |
| `unguarded_goroutine` | `go func() { ... }()` with multiple calls and no error check, channel send, or log |

Generated files (`// Code generated`) and `_test.go` files are skipped.
