package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/leazelaya/bug-hunter/internal/mcpserver"
	"github.com/leazelaya/bug-hunter/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "Path to archaeologist SQLite DB (required)")
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "hunter-mcp: --db is required")
		os.Exit(1)
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hunter-mcp: open db: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	srv := mcpserver.New(s)
	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "hunter-mcp: %v\n", err)
		os.Exit(1)
	}
}
