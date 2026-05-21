package mcpserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/leazelaya/bug-hunter/internal/store"
)

// newTestServer creates an MCP server backed by an in-memory DB pre-seeded with data.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Seed file_stats so hotspot JOIN works.
	s.UpsertFileStats(store.FileStats{FileID: 1, FixRatio: 0.8, RiskScore: 2.0})
	s.UpsertFileStats(store.FileStats{FileID: 2, FixRatio: 0.5, RiskScore: 1.0})

	// Seed findings.
	s.InsertFinding(store.Finding{FileID: 1, Kind: "fix_hotspot", Severity: "high",
		Message: "fix ratio 80%", Path: "hot.go", BlastRisk: 2.0, BlastRadius: 10})
	s.InsertFinding(store.Finding{FileID: 2, Kind: "fix_hotspot", Severity: "medium",
		Message: "fix ratio 50%", Path: "warm.go", BlastRisk: 1.0, BlastRadius: 5})
	s.InsertFinding(store.Finding{FileID: 1, Kind: "silent_error", Severity: "medium",
		Message: "ignored error at line 42", Path: "hot.go", Line: 42})
	s.InsertFinding(store.Finding{FileID: 2, Kind: "bus_factor_1", Severity: "medium",
		Message: "single author", Path: "warm.go"})

	// Seed co-change.
	s.UpsertCoChange(store.CoChange{FileA: 1, FileB: 2, CoCommits: 5, HasEdge: false})

	// Create the archaeologist files table (not in hunter migration) and seed it.
	s.DB().Exec(`CREATE TABLE IF NOT EXISTS files (
		id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
		package TEXT NOT NULL DEFAULT '', loc INTEGER NOT NULL DEFAULT 0,
		is_test INTEGER NOT NULL DEFAULT 0, is_generated INTEGER NOT NULL DEFAULT 0,
		language TEXT NOT NULL DEFAULT 'go')`)
	s.DB().Exec(`INSERT OR IGNORE INTO files(id,path,package,loc,is_test,is_generated,language) VALUES(1,'hot.go','p',10,0,0,'go')`)
	s.DB().Exec(`INSERT OR IGNORE INTO files(id,path,package,loc,is_test,is_generated,language) VALUES(2,'warm.go','p',10,0,0,'go')`)

	return New(s)
}

// roundtrip sends one JSON-RPC request to the server and returns the parsed response.
func roundtrip(t *testing.T, srv *Server, req map[string]any) map[string]json.RawMessage {
	t.Helper()
	reqBytes, _ := json.Marshal(req)
	in := bytes.NewReader(append(reqBytes, '\n'))
	var out bytes.Buffer
	srv.in = in
	srv.out = &out

	if err := srv.Run(); err != nil {
		t.Fatalf("server.Run: %v", err)
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("parse response %q: %v", out.String(), err)
	}
	return resp
}

func toolText(t *testing.T, resp map[string]json.RawMessage) string {
	t.Helper()
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp["result"], &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("empty content")
	}
	return result.Content[0].Text
}

// ---- tests ----

func TestServer_Initialize(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{},
	})
	var result map[string]any
	json.Unmarshal(resp["result"], &result)
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}
}

func TestServer_ToolsList(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{},
	})
	var result struct {
		Tools []struct{ Name string `json:"name"` } `json:"tools"`
	}
	json.Unmarshal(resp["result"], &result)
	names := make(map[string]bool)
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"hotspot_files", "silent_errors", "implicit_couplings", "bug_risk_for_change"} {
		if !names[want] {
			t.Errorf("tool %q missing from tools/list", want)
		}
	}
}

func TestServer_HotspotFiles(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "hotspot_files",
			"arguments": map[string]any{"limit": 5},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "hot.go") {
		t.Errorf("expected hot.go in hotspot output, got:\n%s", text)
	}
	if !strings.Contains(text, "Fix Hotspots") {
		t.Errorf("expected title in output, got:\n%s", text)
	}
}

func TestServer_SilentErrors(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "silent_errors",
			"arguments": map[string]any{"limit": 10},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "hot.go") {
		t.Errorf("expected hot.go in silent_errors output, got:\n%s", text)
	}
	if !strings.Contains(text, "ignored error at line 42") {
		t.Errorf("expected finding message in output, got:\n%s", text)
	}
}

func TestServer_SilentErrors_PathFilter(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "silent_errors",
			"arguments": map[string]any{"path": "warm", "limit": 10},
		},
	})
	text := toolText(t, resp)
	// warm.go has no silent_error findings.
	if strings.Contains(text, "hot.go") {
		t.Errorf("path filter 'warm' should exclude hot.go, got:\n%s", text)
	}
}

func TestServer_ImplicitCouplings(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "implicit_couplings",
			"arguments": map[string]any{"limit": 10},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "hot.go") || !strings.Contains(text, "warm.go") {
		t.Errorf("expected both files in coupling output, got:\n%s", text)
	}
}

func TestServer_BugRiskForChange_Files(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "bug_risk_for_change",
			"arguments": map[string]any{"files": []string{"hot.go"}},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "hot.go") {
		t.Errorf("expected hot.go findings, got:\n%s", text)
	}
}

func TestServer_BugRiskForChange_Diff(t *testing.T) {
	srv := newTestServer(t)
	diff := "--- a/hot.go\n+++ b/hot.go\n@@ -1 +1 @@\n-old\n+new\n"
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "bug_risk_for_change",
			"arguments": map[string]any{"diff": diff},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "hot.go") {
		t.Errorf("diff input should resolve to hot.go findings, got:\n%s", text)
	}
}

func TestServer_BugRiskForChange_UnknownFile(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "bug_risk_for_change",
			"arguments": map[string]any{"files": []string{"nonexistent.go"}},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "No historical bug signals") {
		t.Errorf("unknown file should return no signals, got:\n%s", text)
	}
}

func TestServer_UnknownMethod(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "unknown/method", "params": map[string]any{},
	})
	if _, hasErr := resp["error"]; !hasErr {
		t.Errorf("expected error for unknown method, got: %v", resp)
	}
}
