package findings

import (
	"testing"

	"github.com/leazelaya/bug-hunter/internal/gitanalysis"
	"github.com/leazelaya/bug-hunter/internal/store"
)

func openTestDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRunGitFindings_Hotspot(t *testing.T) {
	s := openTestDB(t)
	results := []gitanalysis.FileResult{
		{FileID: 1, Path: "hot.go", TotalCommits: 5, FixCommits: 3, FixRatio: 0.6, UniqueAuthors: 2, BusFactor: 2},
		{FileID: 2, Path: "cold.go", TotalCommits: 10, FixCommits: 1, FixRatio: 0.1, UniqueAuthors: 2, BusFactor: 2},
	}
	blast := map[int64]store.BlastMetric{}

	if err := RunGitFindings(s, results, blast); err != nil {
		t.Fatal(err)
	}

	var count int
	s.DB().QueryRow(`SELECT COUNT(*) FROM hunter_findings WHERE kind='fix_hotspot'`).Scan(&count)
	if count != 1 {
		t.Errorf("fix_hotspot count = %d, want 1 (only hot.go should be above threshold)", count)
	}

	var path string
	s.DB().QueryRow(`SELECT path FROM hunter_findings WHERE kind='fix_hotspot'`).Scan(&path)
	if path != "hot.go" {
		t.Errorf("hotspot path = %q, want %q", path, "hot.go")
	}
}

func TestRunGitFindings_Severity(t *testing.T) {
	s := openTestDB(t)
	results := []gitanalysis.FileResult{
		// High blast risk + high fix ratio → high severity.
		{FileID: 1, Path: "a.go", TotalCommits: 2, FixCommits: 2, FixRatio: 1.0, UniqueAuthors: 1, BusFactor: 2},
		// Low fix ratio alone → medium.
		{FileID: 2, Path: "b.go", TotalCommits: 10, FixCommits: 4, FixRatio: 0.4, UniqueAuthors: 2, BusFactor: 2},
	}
	blast := map[int64]store.BlastMetric{
		1: {FileID: 1, RiskScore: 5.0, TransitiveIn: 100}, // score = 1.0 * (1+5) = 6 → high
	}

	if err := RunGitFindings(s, results, blast); err != nil {
		t.Fatal(err)
	}

	var sev1, sev2 string
	s.DB().QueryRow(`SELECT severity FROM hunter_findings WHERE file_id=1 AND kind='fix_hotspot'`).Scan(&sev1)
	s.DB().QueryRow(`SELECT severity FROM hunter_findings WHERE file_id=2 AND kind='fix_hotspot'`).Scan(&sev2)

	if sev1 != "high" {
		t.Errorf("file 1 severity = %q, want high", sev1)
	}
	if sev2 != "medium" {
		t.Errorf("file 2 severity = %q, want medium", sev2)
	}
}

func TestRunGitFindings_BusFactor1(t *testing.T) {
	s := openTestDB(t)
	results := []gitanalysis.FileResult{
		{FileID: 1, Path: "solo.go", TotalCommits: 5, FixCommits: 1, FixRatio: 0.2, UniqueAuthors: 1, BusFactor: 1},
		{FileID: 2, Path: "team.go", TotalCommits: 5, FixCommits: 1, FixRatio: 0.2, UniqueAuthors: 3, BusFactor: 3},
	}

	if err := RunGitFindings(s, results, nil); err != nil {
		t.Fatal(err)
	}

	var count int
	s.DB().QueryRow(`SELECT COUNT(*) FROM hunter_findings WHERE kind='bus_factor_1'`).Scan(&count)
	if count != 1 {
		t.Errorf("bus_factor_1 count = %d, want 1", count)
	}
	var path string
	s.DB().QueryRow(`SELECT path FROM hunter_findings WHERE kind='bus_factor_1'`).Scan(&path)
	if path != "solo.go" {
		t.Errorf("bus_factor_1 path = %q, want solo.go", path)
	}
}

func TestRunGitFindings_BlastRiskInStats(t *testing.T) {
	s := openTestDB(t)
	results := []gitanalysis.FileResult{
		{FileID: 1, Path: "a.go", TotalCommits: 2, FixCommits: 2, FixRatio: 1.0, UniqueAuthors: 1, BusFactor: 1},
	}
	blast := map[int64]store.BlastMetric{
		1: {FileID: 1, RiskScore: 3.0, TransitiveIn: 50},
	}

	if err := RunGitFindings(s, results, blast); err != nil {
		t.Fatal(err)
	}

	var riskScore float64
	s.DB().QueryRow(`SELECT risk_score FROM hunter_file_stats WHERE file_id=1`).Scan(&riskScore)
	// fix_ratio * (1 + blast_risk) = 1.0 * 4.0 = 4.0
	if riskScore < 3.9 || riskScore > 4.1 {
		t.Errorf("risk_score = %.4f, want ~4.0", riskScore)
	}
}

func TestRunCoChangeFindings_ImplicitCoupling(t *testing.T) {
	s := openTestDB(t)
	// The in-memory DB has no edges table, so HasEdge will return false for all pairs.
	pairs := []gitanalysis.CoChangePair{
		{FileA: 1, FileB: 2, CoCommits: 5},
		{FileA: 3, FileB: 4, CoCommits: 3},
	}
	filePaths := map[int64]string{1: "a.go", 2: "b.go", 3: "c.go", 4: "d.go"}

	if err := RunCoChangeFindings(s, pairs, filePaths); err != nil {
		t.Fatal(err)
	}

	var count int
	s.DB().QueryRow(`SELECT COUNT(*) FROM hunter_cochange WHERE has_edge=0`).Scan(&count)
	if count != 2 {
		t.Errorf("cochange rows = %d, want 2", count)
	}

	var findingCount int
	s.DB().QueryRow(`SELECT COUNT(*) FROM hunter_findings WHERE kind='implicit_coupling'`).Scan(&findingCount)
	if findingCount != 2 {
		t.Errorf("implicit_coupling findings = %d, want 2", findingCount)
	}
}
