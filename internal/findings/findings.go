package findings

import (
	"fmt"
	"time"

	"github.com/leazelaya/bug-hunter/internal/gitanalysis"
	"github.com/leazelaya/bug-hunter/internal/store"
)

const (
	fixRatioThreshold = 0.4
)

// severity levels
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
)

// RunGitFindings populates hunter_file_stats and writes git-based findings.
// It does NOT clear existing findings — callers should call store.ClearFindings() first.
func RunGitFindings(s *store.Store, results []gitanalysis.FileResult, blast map[int64]store.BlastMetric) error {
	for _, r := range results {
		bm := blast[r.FileID]

		// Compute composite risk score: fix_ratio × (1 + blast_risk).
		riskScore := r.FixRatio * (1 + bm.RiskScore)

		fs := store.FileStats{
			FileID:        r.FileID,
			TotalCommits:  r.TotalCommits,
			FixCommits:    r.FixCommits,
			FixRatio:      r.FixRatio,
			UniqueAuthors: r.UniqueAuthors,
			LastFixTS:     r.LastFixTS,
			BusFactor:     r.BusFactor,
			RiskScore:     riskScore,
		}
		if err := s.UpsertFileStats(fs); err != nil {
			return fmt.Errorf("upsert file stats %d: %w", r.FileID, err)
		}

		// Finding: fix hotspot.
		if r.FixRatio >= fixRatioThreshold {
			sev := severity(r.FixRatio, bm.RiskScore)
			lastFix := ""
			if r.LastFixTS > 0 {
				lastFix = fmt.Sprintf(", last fix %s", time.Unix(r.LastFixTS, 0).Format("2006-01-02"))
			}
			msg := fmt.Sprintf(
				"fix ratio %.0f%% (%d/%d commits%s)",
				r.FixRatio*100, r.FixCommits, r.TotalCommits, lastFix,
			)
			if _, err := s.InsertFinding(store.Finding{
				FileID:      r.FileID,
				Kind:        "fix_hotspot",
				Severity:    sev,
				Message:     msg,
				Path:        r.Path,
				BlastRadius: bm.TransitiveIn,
				BlastRisk:   bm.RiskScore,
			}); err != nil {
				return fmt.Errorf("insert hotspot finding: %w", err)
			}
		}

		// Finding: bus factor 1 with inactive author.
		if r.BusFactor == 1 && r.UniqueAuthors == 1 {
			msg := fmt.Sprintf("single author, bus factor 1 (%d commits)", r.TotalCommits)
			sev := SevMedium
			if r.FixRatio >= fixRatioThreshold {
				sev = SevHigh
			}
			if _, err := s.InsertFinding(store.Finding{
				FileID:      r.FileID,
				Kind:        "bus_factor_1",
				Severity:    sev,
				Message:     msg,
				Path:        r.Path,
				BlastRadius: bm.TransitiveIn,
				BlastRisk:   bm.RiskScore,
			}); err != nil {
				return fmt.Errorf("insert bus_factor finding: %w", err)
			}
		}
	}
	return nil
}

// RunCoChangeFindings writes co-change findings, checking the call graph for edges.
func RunCoChangeFindings(s *store.Store, pairs []gitanalysis.CoChangePair, filePaths map[int64]string) error {
	for _, p := range pairs {
		hasEdge, err := s.HasEdge(p.FileA, p.FileB)
		if err != nil {
			return err
		}
		if err := s.UpsertCoChange(store.CoChange{
			FileA:     p.FileA,
			FileB:     p.FileB,
			CoCommits: p.CoCommits,
			HasEdge:   hasEdge,
		}); err != nil {
			return fmt.Errorf("upsert cochange: %w", err)
		}
		if !hasEdge {
			pathA := filePaths[p.FileA]
			pathB := filePaths[p.FileB]
			qualifier := ""
			if p.IsFixCoChange {
				qualifier = " (including fix commits)"
			}
			msg := fmt.Sprintf(
				"co-changed %d times%s but no call-graph edge between %s and %s",
				p.CoCommits, qualifier, pathA, pathB,
			)
			if _, err := s.InsertFinding(store.Finding{
				FileID:   p.FileA,
				Kind:     "implicit_coupling",
				Severity: SevMedium,
				Message:  msg,
				Path:     pathA,
			}); err != nil {
				return fmt.Errorf("insert implicit_coupling finding: %w", err)
			}
		}
	}
	return nil
}

func severity(fixRatio, blastRisk float64) string {
	score := fixRatio*(1+blastRisk)
	switch {
	case score >= 0.7:
		return SevHigh
	case score >= 0.4:
		return SevMedium
	default:
		return SevLow
	}
}
