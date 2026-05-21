package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS hunter_file_stats (
    file_id         INTEGER PRIMARY KEY,
    total_commits   INTEGER NOT NULL DEFAULT 0,
    fix_commits     INTEGER NOT NULL DEFAULT 0,
    fix_ratio       REAL NOT NULL DEFAULT 0,
    unique_authors  INTEGER NOT NULL DEFAULT 0,
    last_fix_ts     INTEGER NOT NULL DEFAULT 0,
    bus_factor      INTEGER NOT NULL DEFAULT 1,
    risk_score      REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hunter_fix_ratio ON hunter_file_stats(fix_ratio DESC);

CREATE TABLE IF NOT EXISTS hunter_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      INTEGER,
    symbol_id    INTEGER,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    message      TEXT NOT NULL,
    path         TEXT NOT NULL,
    line         INTEGER NOT NULL DEFAULT 0,
    blast_radius INTEGER NOT NULL DEFAULT 0,
    blast_risk   REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hunter_findings_sev ON hunter_findings(severity, blast_risk DESC);

CREATE TABLE IF NOT EXISTS hunter_cochange (
    file_a     INTEGER NOT NULL,
    file_b     INTEGER NOT NULL,
    co_commits INTEGER NOT NULL DEFAULT 0,
    has_edge   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_a, file_b)
);

CREATE TABLE IF NOT EXISTS hunter_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`)
	return err
}

// SetMeta upserts a key/value in hunter_meta.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO hunter_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	return err
}

// GetMeta returns a value from hunter_meta, or "" if not found.
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM hunter_meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}
