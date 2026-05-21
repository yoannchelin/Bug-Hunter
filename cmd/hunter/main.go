package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leazelaya/bug-hunter/internal/codeanalysis"
	"github.com/leazelaya/bug-hunter/internal/findings"
	"github.com/leazelaya/bug-hunter/internal/gitanalysis"
	"github.com/leazelaya/bug-hunter/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}

	switch os.Args[1] {
	case "scan":
		return cmdScan(os.Args[2:])
	case "hotspots":
		return cmdHotspots(os.Args[2:])
	case "findings":
		return cmdFindings(os.Args[2:])
	default:
		usage()
		return nil
	}
}

func usage() {
	fmt.Println(`hunter — Bug Hunter CLI

Commands:
  scan      --db <path>  [--repo <path>]   Analyse git history + code, write findings
  hotspots  --db <path>  [--top <n>]       Print top hotspot files
  findings  --db <path>  [--severity <s>]  Print findings (high|medium|low)`)
}

// ---- scan ----

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to archaeologist SQLite DB (required)")
	repoPath := fs.String("repo", "", "Path to Git repository root (for AST analysis)")
	noAST := fs.Bool("no-ast", false, "Skip AST analysis (faster on large repos)")
	_ = fs.Parse(args)

	if *dbPath == "" {
		return fmt.Errorf("--db is required")
	}

	fmt.Fprintf(os.Stderr, "[hunter] opening db %s\n", *dbPath)
	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()

	// Clear previous hunter data.
	_ = s.ClearFindings()
	_ = s.ClearCoChange()
	_ = s.ClearFileStats()

	fmt.Fprintf(os.Stderr, "[hunter] loading file commits…\n")
	fcs, err := s.LoadAllFileCommits()
	if err != nil {
		return fmt.Errorf("load file commits: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[hunter] loaded %d file-commit rows\n", len(fcs))

	fmt.Fprintf(os.Stderr, "[hunter] analysing git history…\n")
	results, pairs := gitanalysis.Analyze(fcs)

	fmt.Fprintf(os.Stderr, "[hunter] loading blast metrics…\n")
	blast, err := s.LoadBlastMetrics()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[hunter] writing git findings…\n")
	if err := findings.RunGitFindings(s, results, blast); err != nil {
		return err
	}

	// Build path→fileID map for co-change findings.
	pathToID := make(map[string]int64, len(results))
	filePaths := make(map[int64]string, len(results))
	for _, r := range results {
		pathToID[r.Path] = r.FileID
		filePaths[r.FileID] = r.Path
	}

	fmt.Fprintf(os.Stderr, "[hunter] writing co-change findings…\n")
	if err := findings.RunCoChangeFindings(s, pairs, filePaths); err != nil {
		return err
	}

	// AST analysis if repo path given and not disabled.
	if *repoPath != "" && !*noAST {
		fmt.Fprintf(os.Stderr, "[hunter] analysing Go AST in %s…\n", *repoPath)
		silentErrs, err := codeanalysis.AnalyzeRepo(*repoPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[hunter] AST warning: %v\n", err)
		} else {
			// Load full path→fileID from the DB (covers files with no commits too).
			allFilePaths, err := s.LoadAllFilePaths()
			if err != nil {
				return fmt.Errorf("load file paths: %w", err)
			}
			for rel, id := range pathToID {
				allFilePaths[rel] = id
			}
			// Normalize silent error paths to relative before mapping.
			repoAbs, _ := filepath.Abs(*repoPath)
			for i := range silentErrs {
				if rel, err2 := filepath.Rel(repoAbs, silentErrs[i].Path); err2 == nil {
					silentErrs[i].Path = rel
				}
			}
			fds := codeanalysis.ToFindings(silentErrs, allFilePaths, blast)
			fmt.Fprintf(os.Stderr, "[hunter] %d silent error findings\n", len(fds))
			for _, fd := range fds {
				if _, err := s.InsertFinding(fd); err != nil {
					return fmt.Errorf("insert silent error finding: %w", err)
				}
			}
		}
	}

	_ = s.SetMeta("last_scan", time.Now().UTC().Format(time.RFC3339))

	if err := printScanSummary(s, len(results)); err != nil {
		fmt.Fprintf(os.Stderr, "[hunter] summary error: %v\n", err)
	}
	return nil
}

func printScanSummary(s *store.Store, filesAnalysed int) error {
	rows, err := s.DB().Query(`
SELECT severity, kind, COUNT(*) FROM hunter_findings
GROUP BY severity, kind
ORDER BY
  CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
  kind`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintf(os.Stderr, "\n[hunter] ── scan summary ──────────────────────────\n")
	fmt.Fprintf(os.Stderr, "[hunter]   files analysed : %d\n", filesAnalysed)

	total := 0
	for rows.Next() {
		var sev, kind string
		var count int
		if err := rows.Scan(&sev, &kind, &count); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[hunter]   %-8s %-20s %d\n", sev, kind, count)
		total += count
	}
	fmt.Fprintf(os.Stderr, "[hunter]   ─────────────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "[hunter]   total findings : %d\n", total)
	fmt.Fprintf(os.Stderr, "[hunter] ─────────────────────────────────────────────\n")
	return rows.Err()
}

// ---- hotspots ----

func cmdHotspots(args []string) error {
	fs := flag.NewFlagSet("hotspots", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite DB (required)")
	top := fs.Int("top", 20, "Number of results")
	_ = fs.Parse(args)

	if *dbPath == "" {
		return fmt.Errorf("--db is required")
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()

	hot, err := s.QueryHotspots(*top, 0.4)
	if err != nil {
		return err
	}

	if len(hot) == 0 {
		fmt.Println("No hotspots found.")
		return nil
	}

	fmt.Printf("%-8s %-8s  %s\n", "SEVERITY", "RISK", "PATH")
	fmt.Println(strings.Repeat("-", 60))
	for _, f := range hot {
		fmt.Printf("%-8s %-8.2f  %s\n", f.Severity, f.BlastRisk, f.Path)
	}
	return nil
}

// ---- findings ----

func cmdFindings(args []string) error {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite DB (required)")
	sev := fs.String("severity", "", "Filter by severity: high|medium|low")
	kind := fs.String("kind", "", "Filter by kind: fix_hotspot|silent_error|bus_factor_1|implicit_coupling")
	top := fs.Int("top", 0, "Limit number of results (0 = all)")
	_ = fs.Parse(args)

	if *dbPath == "" {
		return fmt.Errorf("--db is required")
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()

	limitN := -1 // SQLite: LIMIT -1 means no limit
	if *top > 0 {
		limitN = *top
	}
	rows, err := s.DB().Query(`
SELECT kind,severity,path,line,message,blast_risk FROM hunter_findings
WHERE (? = '' OR severity = ?)
  AND (? = '' OR kind = ?)
ORDER BY
  CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
  blast_risk DESC
LIMIT ?`, *sev, *sev, *kind, *kind, limitN)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var kind, severity, path, message string
		var line int
		var blastRisk float64
		if err := rows.Scan(&kind, &severity, &path, &line, &message, &blastRisk); err != nil {
			return err
		}
		count++
		lineStr := ""
		if line > 0 {
			lineStr = fmt.Sprintf(":%d", line)
		}
		fmt.Printf("[%s] %s  %s%s\n  %s\n\n", severity, kind, path, lineStr, message)
	}
	if count == 0 {
		fmt.Println("No findings.")
	}
	return rows.Err()
}
