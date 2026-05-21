package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/leazelaya/bug-hunter/internal/store"
)

// Server implements the MCP stdio protocol for Bug Hunter.
type Server struct {
	store *store.Store
	in    io.Reader
	out   io.Writer
}

func New(s *store.Store) *Server {
	return &Server{store: s, in: os.Stdin, out: os.Stdout}
}

// Run reads JSON-RPC 2.0 messages from stdin and writes responses to stdout.
func (srv *Server) Run() error {
	dec := json.NewDecoder(srv.in)
	for {
		var req map[string]json.RawMessage
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("decode: %w", err)
		}
		resp := srv.handle(req)
		if err := json.NewEncoder(srv.out).Encode(resp); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
}

func (srv *Server) handle(req map[string]json.RawMessage) map[string]any {
	id := req["id"]
	methodRaw := req["method"]
	var method string
	_ = json.Unmarshal(methodRaw, &method)

	var params map[string]json.RawMessage
	_ = json.Unmarshal(req["params"], &params)

	switch method {
	case "initialize":
		return jsonrpcResult(id, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "bug-hunter", "version": "0.1.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})

	case "tools/list":
		return jsonrpcResult(id, map[string]any{"tools": toolList()})

	case "tools/call":
		var callParams struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req["params"], &callParams)
		result, err := srv.callTool(callParams.Name, callParams.Arguments)
		if err != nil {
			return jsonrpcError(id, -32603, err.Error())
		}
		return jsonrpcResult(id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": result}},
		})

	default:
		return jsonrpcError(id, -32601, "method not found: "+method)
	}
}

func (srv *Server) callTool(name string, args map[string]json.RawMessage) (string, error) {
	switch name {
	case "hotspot_files":
		return srv.toolHotspots(args)
	case "silent_errors":
		return srv.toolSilentErrors(args)
	case "implicit_couplings":
		return srv.toolImplicitCouplings(args)
	case "bug_risk_for_change":
		return srv.toolBugRiskForChange(args)
	case "code_health_summary":
		return srv.toolCodeHealthSummary(args)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// ---- tool: hotspot_files ----

func (srv *Server) toolHotspots(args map[string]json.RawMessage) (string, error) {
	limit := intArg(args, "limit", 20)
	minFixRatio := floatArg(args, "min_fix_ratio", 0.4)

	findings, err := srv.store.QueryHotspots(limit, minFixRatio)
	if err != nil {
		return "", err
	}
	return renderFindings("Fix Hotspots", findings), nil
}

// ---- tool: silent_errors ----

func (srv *Server) toolSilentErrors(args map[string]json.RawMessage) (string, error) {
	path := stringArg(args, "path", "")
	limit := intArg(args, "limit", 50)

	findings, err := srv.store.QuerySilentErrors(path, limit)
	if err != nil {
		return "", err
	}
	return renderFindings("Silent Errors", findings), nil
}

// ---- tool: implicit_couplings ----

func (srv *Server) toolImplicitCouplings(args map[string]json.RawMessage) (string, error) {
	limit := intArg(args, "limit", 20)

	pairs, err := srv.store.QueryImplicitCouplings(limit)
	if err != nil {
		return "", err
	}
	if len(pairs) == 0 {
		return "No implicit couplings detected.", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Implicit Couplings (%d pairs, co-change without call-graph edge)\n\n", len(pairs))
	fmt.Fprintf(&sb, "%-6s  %s\n------  -----\n", "Commits", "Files")
	for _, p := range pairs {
		fmt.Fprintf(&sb, "%-6d  %s ↔ %s\n", p.CoCommits, p.PathA, p.PathB)
	}
	return sb.String(), nil
}

// ---- tool: bug_risk_for_change ----

func (srv *Server) toolBugRiskForChange(args map[string]json.RawMessage) (string, error) {
	var files []string
	if raw, ok := args["files"]; ok {
		_ = json.Unmarshal(raw, &files)
	}

	// If a unified diff is provided instead of (or in addition to) files, extract paths from it.
	if raw, ok := args["diff"]; ok {
		var diff string
		if err := json.Unmarshal(raw, &diff); err == nil && diff != "" {
			files = append(files, pathsFromDiff(diff)...)
		}
	}

	// Deduplicate paths.
	seen := make(map[string]bool)
	unique := files[:0]
	for _, p := range files {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	files = unique

	// Resolve paths to file IDs.
	var fileIDs []int64
	for _, p := range files {
		id, found, err := srv.store.FileIDByPath(p)
		if err != nil {
			return "", err
		}
		if found {
			fileIDs = append(fileIDs, id)
		}
	}

	findings, err := srv.store.QueryFindingsForFiles(fileIDs)
	if err != nil {
		return "", err
	}
	if len(findings) == 0 {
		return "No historical bug signals found for the provided files.", nil
	}
	return renderFindings("Bug Risk for Change", findings), nil
}

// ---- tool: code_health_summary ----

func (srv *Server) toolCodeHealthSummary(_ map[string]json.RawMessage) (string, error) {
	lastScan, _ := srv.store.GetMeta("last_scan")

	// Counts by severity.
	type sevRow struct{ sev string; count int }
	var sevRows []sevRow
	rows, err := srv.store.DB().Query(`
SELECT severity, COUNT(*) FROM hunter_findings GROUP BY severity
ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r sevRow
		rows.Scan(&r.sev, &r.count)
		sevRows = append(sevRows, r)
	}
	rows.Close()

	// Counts by kind.
	type kindRow struct{ kind string; count int }
	var kindRows []kindRow
	rows, err = srv.store.DB().Query(`
SELECT kind, COUNT(*) FROM hunter_findings GROUP BY kind ORDER BY COUNT(*) DESC`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r kindRow
		rows.Scan(&r.kind, &r.count)
		kindRows = append(kindRows, r)
	}
	rows.Close()

	// Top 5 hotspot files.
	hotspots, err := srv.store.QueryHotspots(5, 0.4)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("## Code Health Summary\n\n")
	if lastScan != "" {
		fmt.Fprintf(&sb, "Last scan: %s\n\n", lastScan)
	}

	sb.WriteString("### Findings by severity\n\n")
	total := 0
	for _, r := range sevRows {
		fmt.Fprintf(&sb, "- **%s**: %d\n", r.sev, r.count)
		total += r.count
	}
	if total == 0 {
		sb.WriteString("No findings — run `hunter scan` first.\n")
		return sb.String(), nil
	}
	fmt.Fprintf(&sb, "- **total**: %d\n\n", total)

	sb.WriteString("### Findings by kind\n\n")
	for _, r := range kindRows {
		fmt.Fprintf(&sb, "- `%s`: %d\n", r.kind, r.count)
	}
	sb.WriteByte('\n')

	if len(hotspots) > 0 {
		sb.WriteString("### Top fix hotspots\n\n")
		for _, f := range hotspots {
			blastStr := ""
			if f.BlastRisk > 0 {
				blastStr = fmt.Sprintf(" (blast_risk=%.1f)", f.BlastRisk)
			}
			fmt.Fprintf(&sb, "- [%s] %s%s\n", f.Severity, f.Path, blastStr)
		}
		sb.WriteByte('\n')
	}

	sb.WriteString("Use `hotspot_files`, `silent_errors`, `implicit_couplings`, or `bug_risk_for_change` to drill down.\n")
	return sb.String(), nil
}

// ---- helpers ----

// renderFindings groups findings by file path for compact, LLM-friendly output.
func renderFindings(title string, findings []store.Finding) string {
	if len(findings) == 0 {
		return fmt.Sprintf("## %s\n\nNo findings.", title)
	}

	// Group by path, preserving insertion order.
	type fileGroup struct {
		path      string
		blastRisk float64
		blastRad  int
		items     []store.Finding
	}
	order := []string{}
	groups := map[string]*fileGroup{}
	for _, f := range findings {
		if _, ok := groups[f.Path]; !ok {
			order = append(order, f.Path)
			groups[f.Path] = &fileGroup{path: f.Path, blastRisk: f.BlastRisk, blastRad: f.BlastRadius}
		}
		g := groups[f.Path]
		if f.BlastRisk > g.blastRisk {
			g.blastRisk = f.BlastRisk
			g.blastRad = f.BlastRadius
		}
		g.items = append(g.items, f)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s (%d findings across %d files)\n\n", title, len(findings), len(order))
	for _, path := range order {
		g := groups[path]
		blastStr := ""
		if g.blastRisk > 0 {
			blastStr = fmt.Sprintf("  blast_radius=%d blast_risk=%.2f", g.blastRad, g.blastRisk)
		}
		fmt.Fprintf(&sb, "### %s (%d)%s\n", g.path, len(g.items), blastStr)
		for _, f := range g.items {
			loc := ""
			if f.Line > 0 {
				loc = fmt.Sprintf(":%d", f.Line)
			}
			fmt.Fprintf(&sb, "- [%s] %s%s — %s\n", f.Severity, f.Kind, loc, f.Message)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func toolList() []map[string]any {
	return []map[string]any{
		{
			"name":        "code_health_summary",
			"description": "High-level overview of all bug signals: finding counts by severity and kind, top hotspot files. Call this first to orient in the codebase.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "hotspot_files",
			"description": "Top files by fix ratio × blast radius — the most dangerous to touch",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit":         map[string]any{"type": "integer", "description": "Max results (default 20)"},
					"min_fix_ratio": map[string]any{"type": "number", "description": "Minimum fix ratio (default 0.4)"},
				},
			},
		},
		{
			"name":        "silent_errors",
			"description": "Files with swallowed exceptions, ignored errors, floating promises, or unsafe type assertions (Go, TypeScript, Python)",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Path prefix filter"},
					"limit": map[string]any{"type": "integer", "description": "Max results (default 50)"},
				},
			},
		},
		{
			"name":        "implicit_couplings",
			"description": "File pairs frequently co-changed in fix commits but with no call-graph edge",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "description": "Max results (default 20)"},
				},
			},
		},
		{
			"name":        "bug_risk_for_change",
			"description": "Given a list of files or a unified diff, returns historical bug signals suggesting risk",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"files": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of file paths relative to repo root",
					},
					"diff": map[string]any{
						"type":        "string",
						"description": "Unified diff (git diff output) — paths extracted automatically",
					},
				},
			},
		},
	}
}

func jsonrpcResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func jsonrpcError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	}
}

func intArg(args map[string]json.RawMessage, key string, def int) int {
	raw, ok := args[key]
	if !ok {
		return def
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil || v == 0 {
		return def
	}
	return v
}

func floatArg(args map[string]json.RawMessage, key string, def float64) float64 {
	raw, ok := args[key]
	if !ok {
		return def
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		return def
	}
	return v
}

func stringArg(args map[string]json.RawMessage, key, def string) string {
	raw, ok := args[key]
	if !ok {
		return def
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return def
	}
	return v
}
