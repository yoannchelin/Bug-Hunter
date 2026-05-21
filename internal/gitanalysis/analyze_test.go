package gitanalysis

import (
	"testing"
	"time"

	"github.com/leazelaya/bug-hunter/internal/store"
)

func TestAnalyze_FixRatio(t *testing.T) {
	now := time.Now().Unix()
	fcs := []store.FileCommit{
		{CommitHash: "a1", FileID: 1, FilePath: "main.go", AuthorName: "alice", AuthorTS: now, Message: "feat: init"},
		{CommitHash: "a2", FileID: 1, FilePath: "main.go", AuthorName: "alice", AuthorTS: now, Message: "fix: nil ptr"},
		{CommitHash: "a3", FileID: 1, FilePath: "main.go", AuthorName: "alice", AuthorTS: now, Message: "fix: off-by-one"},
		{CommitHash: "b1", FileID: 2, FilePath: "util.go", AuthorName: "alice", AuthorTS: now, Message: "feat: helpers"},
	}

	results, _ := Analyze(fcs)

	byID := make(map[int64]FileResult)
	for _, r := range results {
		byID[r.FileID] = r
	}

	r1 := byID[1]
	if r1.TotalCommits != 3 {
		t.Errorf("file 1: TotalCommits = %d, want 3", r1.TotalCommits)
	}
	if r1.FixCommits != 2 {
		t.Errorf("file 1: FixCommits = %d, want 2", r1.FixCommits)
	}
	if got := r1.FixRatio; got < 0.66 || got > 0.67 {
		t.Errorf("file 1: FixRatio = %.4f, want ~0.666", got)
	}

	r2 := byID[2]
	if r2.FixRatio != 0 {
		t.Errorf("file 2: FixRatio = %v, want 0", r2.FixRatio)
	}
}

func TestAnalyze_MergeCommitsSkipped(t *testing.T) {
	now := time.Now().Unix()
	fcs := []store.FileCommit{
		{CommitHash: "m1", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "Merge pull request #1 from fix/something"},
		{CommitHash: "c1", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "feat: real commit"},
	}

	results, _ := Analyze(fcs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TotalCommits != 1 {
		t.Errorf("merge commit should be skipped; TotalCommits = %d, want 1", results[0].TotalCommits)
	}
	// merge message contains "fix" — should NOT count as a fix commit after merge filter
	if results[0].FixCommits != 0 {
		t.Errorf("merge commit should not count as fix; FixCommits = %d, want 0", results[0].FixCommits)
	}
}

func TestAnalyze_CoChange(t *testing.T) {
	now := time.Now().Unix()
	// Files 1 and 2 co-change in 3 fix commits → should produce a pair.
	// Files 1 and 3 co-change in 2 fix commits → below threshold, no pair.
	fcs := []store.FileCommit{
		{CommitHash: "f1", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "fix: a"},
		{CommitHash: "f1", FileID: 2, FilePath: "b.go", AuthorName: "alice", AuthorTS: now, Message: "fix: a"},
		{CommitHash: "f2", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "fix: b"},
		{CommitHash: "f2", FileID: 2, FilePath: "b.go", AuthorName: "alice", AuthorTS: now, Message: "fix: b"},
		{CommitHash: "f3", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "fix: c"},
		{CommitHash: "f3", FileID: 2, FilePath: "b.go", AuthorName: "alice", AuthorTS: now, Message: "fix: c"},
		{CommitHash: "f4", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "fix: d"},
		{CommitHash: "f4", FileID: 3, FilePath: "c.go", AuthorName: "alice", AuthorTS: now, Message: "fix: d"},
		{CommitHash: "f5", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: now, Message: "fix: e"},
		{CommitHash: "f5", FileID: 3, FilePath: "c.go", AuthorName: "alice", AuthorTS: now, Message: "fix: e"},
	}

	_, pairs := Analyze(fcs)

	found12 := false
	for _, p := range pairs {
		a, b := p.FileA, p.FileB
		if (a == 1 && b == 2) || (a == 2 && b == 1) {
			found12 = true
			if p.CoCommits != 3 {
				t.Errorf("pair (1,2): CoCommits = %d, want 3", p.CoCommits)
			}
		}
		if (a == 1 && b == 3) || (a == 3 && b == 1) {
			t.Errorf("pair (1,3) with 2 co-changes should be below threshold and absent")
		}
	}
	if !found12 {
		t.Errorf("expected co-change pair (1,2) with 3 co-commits, not found in %v", pairs)
	}
}

func TestAnalyze_BusFactor(t *testing.T) {
	// Single author who is inactive → bus_factor = 1.
	old := time.Now().Add(-365 * 24 * time.Hour).Unix() // 1 year ago
	fcs := []store.FileCommit{
		{CommitHash: "x1", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: old, Message: "feat"},
		{CommitHash: "x2", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: old, Message: "feat"},
		{CommitHash: "x3", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: old, Message: "feat"},
		// Recent commit by bob — keeps the repo "alive" so alice is considered inactive.
		{CommitHash: "x4", FileID: 2, FilePath: "b.go", AuthorName: "bob", AuthorTS: time.Now().Unix(), Message: "feat"},
	}

	results, _ := Analyze(fcs)

	byID := make(map[int64]FileResult)
	for _, r := range results {
		byID[r.FileID] = r
	}

	if byID[1].BusFactor != 1 {
		t.Errorf("file 1 single inactive author: BusFactor = %d, want 1", byID[1].BusFactor)
	}
}

func TestAnalyze_LastFixTS(t *testing.T) {
	ts1 := int64(1_000_000)
	ts2 := int64(2_000_000)
	fcs := []store.FileCommit{
		{CommitHash: "c1", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: ts1, Message: "fix: early"},
		{CommitHash: "c2", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: ts2, Message: "fix: later"},
		{CommitHash: "c3", FileID: 1, FilePath: "a.go", AuthorName: "alice", AuthorTS: ts1, Message: "feat: unrelated"},
	}

	results, _ := Analyze(fcs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].LastFixTS != ts2 {
		t.Errorf("LastFixTS = %d, want %d", results[0].LastFixTS, ts2)
	}
}
