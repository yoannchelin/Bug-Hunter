package gitanalysis

import (
	"sort"
	"time"

	"github.com/leazelaya/bug-hunter/internal/store"
)

// FileResult holds computed statistics for one file.
type FileResult struct {
	FileID        int64
	Path          string
	TotalCommits  int
	FixCommits    int
	FixRatio      float64
	UniqueAuthors int
	LastFixTS     int64
	BusFactor     int // 1 when a single author owns the majority
}

// CoChangePair counts how many commits two files were modified together.
type CoChangePair struct {
	FileA        int64
	FileB        int64
	CoCommits    int
	IsFixCoChange bool // true if the pair co-changed in at least one fix commit
}

const (
	minCoChangeCount      = 3 // default minimum; lowered for small commit windows
	smallWindowCommits    = 200
	smallWindowThreshold  = 2
)

// Analyze processes all file-commit rows and returns per-file stats plus co-change pairs.
func Analyze(fcs []store.FileCommit) ([]FileResult, []CoChangePair) {
	type fileAcc struct {
		path        string
		total       int
		fix         int
		lastFixTS   int64
		authorCount map[string]int
	}

	files := make(map[int64]*fileAcc)
	// fixCommit → set of file_ids in that commit
	fixCommitFiles := make(map[string][]int64)
	// all commits → set of file_ids (to detect co-change within fix commits only)
	commitFiles := make(map[string][]int64)
	commitIsFix := make(map[string]bool)

	for _, fc := range fcs {
		if IsMergeCommit(fc.Message) {
			continue
		}
		acc, ok := files[fc.FileID]
		if !ok {
			acc = &fileAcc{path: fc.FilePath, authorCount: make(map[string]int)}
			files[fc.FileID] = acc
		}
		acc.total++
		acc.authorCount[fc.AuthorName]++

		isFix := IsFixCommit(fc.Message)
		commitIsFix[fc.CommitHash] = isFix
		if isFix {
			acc.fix++
			if fc.AuthorTS > acc.lastFixTS {
				acc.lastFixTS = fc.AuthorTS
			}
		}
		commitFiles[fc.CommitHash] = appendUniq(commitFiles[fc.CommitHash], fc.FileID)
		if isFix {
			fixCommitFiles[fc.CommitHash] = appendUniq(fixCommitFiles[fc.CommitHash], fc.FileID)
		}
	}

	// Determine "inactive author" threshold: last 6 months relative to most-recent commit.
	var maxTS int64
	for _, fc := range fcs {
		if fc.AuthorTS > maxTS {
			maxTS = fc.AuthorTS
		}
	}
	inactiveThreshold := maxTS - int64((6 * 30 * 24 * time.Hour).Seconds())

	// Build per-author last-seen map.
	authorLastSeen := make(map[string]int64)
	for _, fc := range fcs {
		if ts := authorLastSeen[fc.AuthorName]; fc.AuthorTS > ts {
			authorLastSeen[fc.AuthorName] = fc.AuthorTS
		}
	}

	// Build results.
	results := make([]FileResult, 0, len(files))
	for fileID, acc := range files {
		ratio := 0.0
		if acc.total > 0 {
			ratio = float64(acc.fix) / float64(acc.total)
		}

		// Bus factor: 1 if a single author wrote >60% of commits.
		busFactor := len(acc.authorCount)
		topAuthor, topCount := "", 0
		for author, cnt := range acc.authorCount {
			if cnt > topCount {
				topCount = cnt
				topAuthor = author
			}
		}
		if float64(topCount)/float64(acc.total) > 0.60 {
			// Check if that author is inactive.
			if authorLastSeen[topAuthor] < inactiveThreshold {
				busFactor = 1
			}
		}

		results = append(results, FileResult{
			FileID:        fileID,
			Path:          acc.path,
			TotalCommits:  acc.total,
			FixCommits:    acc.fix,
			FixRatio:      ratio,
			UniqueAuthors: len(acc.authorCount),
			LastFixTS:     acc.lastFixTS,
			BusFactor:     busFactor,
		})
	}

	// Co-change: count pairs across ALL commits (not just fix commits).
	// This gives a much richer signal in repos with small commit windows.
	// We also track whether the pair co-changed in at least one fix commit.
	totalCommits := len(commitFiles)
	threshold := minCoChangeCount
	if totalCommits < smallWindowCommits {
		threshold = smallWindowThreshold
	}

	coMap := make(map[[2]int64]int)
	fixCoMap := make(map[[2]int64]bool)

	for hash, ids := range commitFiles {
		if len(ids) < 2 {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		isFix := commitIsFix[hash]
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				key := [2]int64{ids[i], ids[j]}
				coMap[key]++
				if isFix {
					fixCoMap[key] = true
				}
			}
		}
	}

	pairs := make([]CoChangePair, 0, len(coMap))
	for k, cnt := range coMap {
		if cnt < threshold {
			continue
		}
		pairs = append(pairs, CoChangePair{
			FileA:         k[0],
			FileB:         k[1],
			CoCommits:     cnt,
			IsFixCoChange: fixCoMap[k],
		})
	}

	return results, pairs
}

func appendUniq(s []int64, v int64) []int64 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
