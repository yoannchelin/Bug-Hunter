package store

import (
	"database/sql"
	"strings"
)

// FileCommit represents a commit touching a file, from the archaeologist schema.
type FileCommit struct {
	CommitHash string
	FileID     int64
	FilePath   string
	AuthorName string
	AuthorTS   int64
	Message    string
}

// BlastMetric holds the blast_metrics row for a file.
type BlastMetric struct {
	FileID       int64
	RiskScore    float64
	TransitiveIn int
}

// FileStats is the hunter_file_stats row.
type FileStats struct {
	FileID        int64
	TotalCommits  int
	FixCommits    int
	FixRatio      float64
	UniqueAuthors int
	LastFixTS     int64
	BusFactor     int
	RiskScore     float64
}

// Finding is the hunter_findings row.
type Finding struct {
	ID          int64
	FileID      int64
	SymbolID    int64
	Kind        string
	Severity    string
	Message     string
	Path        string
	Line        int
	BlastRadius int
	BlastRisk   float64
}

// CoChange is the hunter_cochange row.
type CoChange struct {
	FileA     int64
	FileB     int64
	CoCommits int
	HasEdge   bool
}

// UpsertFileStats writes a hunter_file_stats row.
func (s *Store) UpsertFileStats(fs FileStats) error {
	_, err := s.db.Exec(`
INSERT INTO hunter_file_stats(file_id,total_commits,fix_commits,fix_ratio,unique_authors,last_fix_ts,bus_factor,risk_score)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(file_id) DO UPDATE SET
    total_commits=excluded.total_commits,
    fix_commits=excluded.fix_commits,
    fix_ratio=excluded.fix_ratio,
    unique_authors=excluded.unique_authors,
    last_fix_ts=excluded.last_fix_ts,
    bus_factor=excluded.bus_factor,
    risk_score=excluded.risk_score`,
		fs.FileID, fs.TotalCommits, fs.FixCommits, fs.FixRatio,
		fs.UniqueAuthors, fs.LastFixTS, fs.BusFactor, fs.RiskScore,
	)
	return err
}

// InsertFinding inserts a finding, returning its id.
func (s *Store) InsertFinding(f Finding) (int64, error) {
	res, err := s.db.Exec(`
INSERT INTO hunter_findings(file_id,symbol_id,kind,severity,message,path,line,blast_radius,blast_risk)
VALUES(?,?,?,?,?,?,?,?,?)`,
		f.FileID, f.SymbolID, f.Kind, f.Severity, f.Message, f.Path, f.Line, f.BlastRadius, f.BlastRisk,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpsertCoChange writes a hunter_cochange row.
func (s *Store) UpsertCoChange(cc CoChange) error {
	hasEdge := 0
	if cc.HasEdge {
		hasEdge = 1
	}
	_, err := s.db.Exec(`
INSERT INTO hunter_cochange(file_a,file_b,co_commits,has_edge)
VALUES(?,?,?,?)
ON CONFLICT(file_a,file_b) DO UPDATE SET
    co_commits=excluded.co_commits,
    has_edge=excluded.has_edge`,
		cc.FileA, cc.FileB, cc.CoCommits, hasEdge,
	)
	return err
}

// LoadAllFileCommits reads all (commit, file, author, ts, message) tuples.
// It joins archaeologist's commits + file_commits + files tables.
// Columns: hash, author, email, ts, subject — no num_parents column exists,
// so we rely on the caller's gitanalysis layer to skip obvious merges via subject heuristic.
func (s *Store) LoadAllFileCommits() ([]FileCommit, error) {
	rows, err := s.db.Query(`
SELECT c.hash, fc.file_id, f.path, c.author, c.ts, c.subject
FROM commits c
JOIN file_commits fc ON fc.commit_hash = c.hash
JOIN files f ON f.id = fc.file_id
ORDER BY c.ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileCommit
	for rows.Next() {
		var fc FileCommit
		if err := rows.Scan(&fc.CommitHash, &fc.FileID, &fc.FilePath, &fc.AuthorName, &fc.AuthorTS, &fc.Message); err != nil {
			return nil, err
		}
		out = append(out, fc)
	}
	return out, rows.Err()
}

// LoadBlastMetrics returns blast_metrics aggregated per file_id.
// blast_metrics is keyed by symbol_id; we join through symbols to get the file.
// Returns empty map if the table is absent or empty.
func (s *Store) LoadBlastMetrics() (map[int64]BlastMetric, error) {
	out := make(map[int64]BlastMetric)
	rows, err := s.db.Query(`
SELECT s.file_id, MAX(bm.risk_score), SUM(bm.transitive_in)
FROM blast_metrics bm
JOIN symbols s ON s.id = bm.symbol_id
WHERE s.file_id IS NOT NULL
GROUP BY s.file_id`)
	if err != nil {
		// Table may not exist if Blast Radius wasn't run.
		return out, nil
	}
	defer rows.Close()
	for rows.Next() {
		var bm BlastMetric
		if err := rows.Scan(&bm.FileID, &bm.RiskScore, &bm.TransitiveIn); err != nil {
			return nil, err
		}
		out[bm.FileID] = bm
	}
	return out, rows.Err()
}

// HasEdge returns true if there is a directed edge (a→b or b→a) in the call graph.
// edges uses src/dst referencing symbol ids; we join through symbols to get file_id.
func (s *Store) HasEdge(fileA, fileB int64) (bool, error) {
	var count int
	err := s.db.QueryRow(`
SELECT COUNT(*) FROM edges e
JOIN symbols sa ON sa.id = e.src
JOIN symbols sb ON sb.id = e.dst
WHERE (sa.file_id=? AND sb.file_id=?) OR (sa.file_id=? AND sb.file_id=?)
LIMIT 1`, fileA, fileB, fileB, fileA).Scan(&count)
	if err != nil {
		return false, nil // edges table may not exist
	}
	return count > 0, nil
}

// QueryHotspots returns top findings of kind fix_hotspot ordered by blast_risk desc.
func (s *Store) QueryHotspots(limit int, minFixRatio float64) ([]Finding, error) {
	rows, err := s.db.Query(`
SELECT f.id,f.file_id,f.symbol_id,f.kind,f.severity,f.message,f.path,f.line,f.blast_radius,f.blast_risk
FROM hunter_findings f
JOIN hunter_file_stats fs ON fs.file_id = f.file_id
WHERE f.kind='fix_hotspot' AND fs.fix_ratio >= ?
ORDER BY f.blast_risk DESC, f.file_id
LIMIT ?`, minFixRatio, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// QuerySilentErrors returns silent_error findings, optionally filtered by path prefix.
func (s *Store) QuerySilentErrors(pathPrefix string, limit int) ([]Finding, error) {
	query := `
SELECT id,file_id,symbol_id,kind,severity,message,path,line,blast_radius,blast_risk
FROM hunter_findings
WHERE kind='silent_error'`
	args := []any{}
	if pathPrefix != "" {
		query += ` AND path LIKE ?`
		args = append(args, pathPrefix+"%")
	}
	query += ` ORDER BY blast_risk DESC, path LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// CoChangeWithPaths is a CoChange row enriched with file paths.
type CoChangeWithPaths struct {
	CoChange
	PathA string
	PathB string
}

// QueryImplicitCouplings returns co-change pairs without call graph edge, with file paths.
func (s *Store) QueryImplicitCouplings(limit int) ([]CoChangeWithPaths, error) {
	rows, err := s.db.Query(`
SELECT cc.file_a, cc.file_b, cc.co_commits, cc.has_edge,
       COALESCE(fa.path,'?') AS path_a,
       COALESCE(fb.path,'?') AS path_b
FROM hunter_cochange cc
LEFT JOIN files fa ON fa.id = cc.file_a
LEFT JOIN files fb ON fb.id = cc.file_b
WHERE cc.has_edge=0
ORDER BY cc.co_commits DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoChangeWithPaths
	for rows.Next() {
		var cc CoChangeWithPaths
		var hasEdge int
		if err := rows.Scan(&cc.FileA, &cc.FileB, &cc.CoCommits, &hasEdge, &cc.PathA, &cc.PathB); err != nil {
			return nil, err
		}
		cc.HasEdge = hasEdge == 1
		out = append(out, cc)
	}
	return out, rows.Err()
}

// QueryFindingsForFiles returns all findings for a set of file_ids.
func (s *Store) QueryFindingsForFiles(fileIDs []int64) ([]Finding, error) {
	if len(fileIDs) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(fileIDs))
	placeholders = placeholders[:len(placeholders)-1] // trim trailing comma
	query := `SELECT id,file_id,symbol_id,kind,severity,message,path,line,blast_radius,blast_risk
FROM hunter_findings WHERE file_id IN (` + placeholders + `) ORDER BY blast_risk DESC`
	args := make([]any, len(fileIDs))
	for i, id := range fileIDs {
		args[i] = id
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FileIDByPath resolves a file path to its id from the archaeologist files table.
func (s *Store) FileIDByPath(path string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM files WHERE path=?`, path).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return id, err == nil, err
}

// LoadAllFilePaths returns a path→fileID map for every file in the archaeologist files table.
func (s *Store) LoadAllFilePaths() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT id, path FROM files`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			return nil, err
		}
		out[path] = id
	}
	return out, rows.Err()
}

// ClearFindings deletes all hunter_findings rows (used before re-scan).
func (s *Store) ClearFindings() error {
	_, err := s.db.Exec(`DELETE FROM hunter_findings`)
	return err
}

// ClearCoChange deletes all hunter_cochange rows.
func (s *Store) ClearCoChange() error {
	_, err := s.db.Exec(`DELETE FROM hunter_cochange`)
	return err
}

// ClearFileStats deletes all hunter_file_stats rows.
func (s *Store) ClearFileStats() error {
	_, err := s.db.Exec(`DELETE FROM hunter_file_stats`)
	return err
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.FileID, &f.SymbolID, &f.Kind, &f.Severity,
			&f.Message, &f.Path, &f.Line, &f.BlastRadius, &f.BlastRisk); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
