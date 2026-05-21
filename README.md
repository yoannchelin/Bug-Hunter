# Bug Hunter

**Bug Hunter** answers the question: *"where did it already bug, and will it bug again?"*

It is the 4th agent in the [Git Archaeologist](https://github.com/yoannchelin/Git-archeologist) ecosystem. It reads the SQLite database produced by Archaeologist and detects four classes of risk signals:

| Signal | What it detects |
|---|---|
| **Fix hotspot** | Files where >40% of commits are bugfixes, weighted by blast radius |
| **Silent error** | Error-handling bugs in Go, TypeScript/JS, and Python source |
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
make test           # runs all unit tests
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
4. Walks the source tree and detects silent error patterns (Go AST + TS/Python text analysis)
5. Writes all findings back into the same DB under `hunter_*` tables

Options:

| Flag | Description |
|---|---|
| `--db` | Path to Archaeologist SQLite DB (required) |
| `--repo` | Path to repo root for static analysis |
| `--no-ast` | Skip Go AST analysis |
| `--no-ts` | Skip TypeScript/JS analysis |
| `--no-py` | Skip Python analysis |

### Show hotspot files

```bash
hunter hotspots --db /path/to/.archaeo/index.db --top 20
```

### Show findings

```bash
hunter findings --db /path/to/.archaeo/index.db
hunter findings --db ... --severity high
hunter findings --db ... --kind silent_error
hunter findings --db ... --kind unsafe_assertion
hunter findings --db ... --kind fix_hotspot --top 10
hunter status    --db /path/to/.archaeo/index.db
```

Valid `--kind` values: `fix_hotspot`, `silent_error`, `unsafe_assertion`, `bus_factor_1`, `implicit_coupling`

---

## MCP server

`hunter-mcp` exposes 5 tools over JSON-RPC 2.0 stdio, compatible with Claude Desktop and any MCP client.

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
| `code_health_summary` | High-level overview: finding counts by severity/kind, top hotspots. **Call this first.** |
| `hotspot_files` | Top files by fix ratio × blast radius |
| `silent_errors` | Files with swallowed exceptions, ignored errors, floating promises, unsafe assertions |
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

### Go (AST analysis)

| Kind | Pattern |
|---|---|
| `ignored_error` | `_ = someCall()` — entire return value discarded |
| `swallowed_panic` | `recover()` as a bare statement with no result capture |
| `lost_error` | `if err != nil { return }` bare return without propagating err |
| `unguarded_goroutine` | `go func() { ... }()` with multiple calls and no error check or channel send |

### TypeScript / JavaScript (text analysis)

| Kind | Pattern |
|---|---|
| `swallowed_exception` | Empty `catch` block or `.catch(() => {})` handler |
| `floating_promise` | Unawaited async call in an async function |
| `swallowed_exception` | `JSON.parse()` without try-catch |
| `unsafe_assertion` | Non-null assertion `!.` bypassing TypeScript null safety |

### Python (text analysis)

| Kind | Pattern |
|---|---|
| `swallowed_exception` | Bare `except:` — catches `KeyboardInterrupt` and `SystemExit` |
| `swallowed_exception` | `except SomeError: pass` — exception silently discarded |
| `swallowed_exception` | `subprocess.run/call()` without `check=True` — non-zero exit ignored |

Generated files (`// Code generated`, `__pycache__`) and test files are skipped.
