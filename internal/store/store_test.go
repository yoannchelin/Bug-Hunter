package store

import (
	"testing"
)

func openTestDB(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrate_TablesExist(t *testing.T) {
	s := openTestDB(t)
	tables := []string{"hunter_file_stats", "hunter_findings", "hunter_cochange", "hunter_meta"}
	for _, table := range tables {
		var count int
		err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
		if err != nil || count != 1 {
			t.Errorf("table %s not found after migration", table)
		}
	}
}

func TestSetGetMeta(t *testing.T) {
	s := openTestDB(t)
	if err := s.SetMeta("last_scan", "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	val, err := s.GetMeta("last_scan")
	if err != nil {
		t.Fatal(err)
	}
	if val != "2026-01-01" {
		t.Errorf("GetMeta = %q, want %q", val, "2026-01-01")
	}

	// Upsert should overwrite.
	if err := s.SetMeta("last_scan", "2026-05-21"); err != nil {
		t.Fatal(err)
	}
	val, _ = s.GetMeta("last_scan")
	if val != "2026-05-21" {
		t.Errorf("after upsert GetMeta = %q, want %q", val, "2026-05-21")
	}

	// Missing key returns "".
	val, err = s.GetMeta("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if val != "" {
		t.Errorf("missing key: GetMeta = %q, want empty", val)
	}
}

func TestUpsertFileStats(t *testing.T) {
	s := openTestDB(t)
	fs := FileStats{FileID: 1, TotalCommits: 10, FixCommits: 4, FixRatio: 0.4, UniqueAuthors: 2, BusFactor: 2, RiskScore: 0.5}
	if err := s.UpsertFileStats(fs); err != nil {
		t.Fatal(err)
	}

	var got FileStats
	err := s.db.QueryRow(`SELECT file_id,total_commits,fix_commits,fix_ratio,unique_authors,bus_factor,risk_score FROM hunter_file_stats WHERE file_id=1`).
		Scan(&got.FileID, &got.TotalCommits, &got.FixCommits, &got.FixRatio, &got.UniqueAuthors, &got.BusFactor, &got.RiskScore)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalCommits != 10 || got.FixCommits != 4 || got.BusFactor != 2 {
		t.Errorf("upserted stats mismatch: %+v", got)
	}

	// Upsert should overwrite.
	fs.TotalCommits = 20
	if err := s.UpsertFileStats(fs); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT total_commits FROM hunter_file_stats WHERE file_id=1`).Scan(&got.TotalCommits)
	if got.TotalCommits != 20 {
		t.Errorf("after upsert TotalCommits = %d, want 20", got.TotalCommits)
	}
}

func TestInsertFinding(t *testing.T) {
	s := openTestDB(t)
	f := Finding{
		FileID:   1,
		Kind:     "fix_hotspot",
		Severity: "high",
		Message:  "fix ratio 80%",
		Path:     "main.go",
		Line:     0,
	}
	id, err := s.InsertFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("InsertFinding returned id=0")
	}

	var kind, sev string
	s.db.QueryRow(`SELECT kind, severity FROM hunter_findings WHERE id=?`, id).Scan(&kind, &sev)
	if kind != "fix_hotspot" || sev != "high" {
		t.Errorf("inserted finding: kind=%q sev=%q", kind, sev)
	}
}

func TestClearFindings(t *testing.T) {
	s := openTestDB(t)
	f := Finding{Kind: "fix_hotspot", Severity: "high", Message: "x", Path: "a.go"}
	s.InsertFinding(f)
	s.InsertFinding(f)

	if err := s.ClearFindings(); err != nil {
		t.Fatal(err)
	}
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM hunter_findings`).Scan(&count)
	if count != 0 {
		t.Errorf("after ClearFindings: count = %d, want 0", count)
	}
}

func TestUpsertCoChange(t *testing.T) {
	s := openTestDB(t)
	cc := CoChange{FileA: 1, FileB: 2, CoCommits: 5, HasEdge: false}
	if err := s.UpsertCoChange(cc); err != nil {
		t.Fatal(err)
	}
	var coCommits, hasEdge int
	s.db.QueryRow(`SELECT co_commits, has_edge FROM hunter_cochange WHERE file_a=1 AND file_b=2`).Scan(&coCommits, &hasEdge)
	if coCommits != 5 || hasEdge != 0 {
		t.Errorf("cochange: co_commits=%d has_edge=%d", coCommits, hasEdge)
	}

	// Upsert with edge.
	cc.CoCommits = 7
	cc.HasEdge = true
	s.UpsertCoChange(cc)
	s.db.QueryRow(`SELECT co_commits, has_edge FROM hunter_cochange WHERE file_a=1 AND file_b=2`).Scan(&coCommits, &hasEdge)
	if coCommits != 7 || hasEdge != 1 {
		t.Errorf("after upsert: co_commits=%d has_edge=%d", coCommits, hasEdge)
	}
}

func TestQueryHotspots(t *testing.T) {
	s := openTestDB(t)

	// Seed file_stats so QueryHotspots JOIN works.
	s.UpsertFileStats(FileStats{FileID: 1, FixRatio: 0.8, RiskScore: 1.0})
	s.UpsertFileStats(FileStats{FileID: 2, FixRatio: 0.3, RiskScore: 0.5}) // below threshold

	s.InsertFinding(Finding{FileID: 1, Kind: "fix_hotspot", Severity: "high", Message: "m", Path: "a.go", BlastRisk: 10})
	s.InsertFinding(Finding{FileID: 2, Kind: "fix_hotspot", Severity: "medium", Message: "m", Path: "b.go", BlastRisk: 5})

	findings, err := s.QueryHotspots(10, 0.4)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("QueryHotspots(minFixRatio=0.4): got %d findings, want 1", len(findings))
	}
	if findings[0].Path != "a.go" {
		t.Errorf("wrong finding returned: %+v", findings[0])
	}
}

func TestQueryFindingsForFiles(t *testing.T) {
	s := openTestDB(t)
	s.InsertFinding(Finding{FileID: 1, Kind: "fix_hotspot", Severity: "high", Message: "x", Path: "a.go"})
	s.InsertFinding(Finding{FileID: 2, Kind: "silent_error", Severity: "medium", Message: "y", Path: "b.go"})
	s.InsertFinding(Finding{FileID: 3, Kind: "bus_factor_1", Severity: "high", Message: "z", Path: "c.go"})

	got, err := s.QueryFindingsForFiles([]int64{1, 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("QueryFindingsForFiles([1,3]): got %d, want 2", len(got))
	}

	// Empty input returns nothing.
	got, err = s.QueryFindingsForFiles(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("nil fileIDs: got %d findings, want 0", len(got))
	}
}
