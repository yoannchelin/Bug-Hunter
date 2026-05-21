package mcpserver

import (
	"bufio"
	"strings"
)

// pathsFromDiff extracts unique file paths touched in a unified diff.
// It looks for `--- a/path` and `+++ b/path` lines, stripping the a/ b/ prefix.
func pathsFromDiff(diff string) []string {
	seen := make(map[string]bool)
	var out []string

	scanner := bufio.NewScanner(strings.NewReader(diff))
	for scanner.Scan() {
		line := scanner.Text()
		var raw string
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			raw = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "--- a/"):
			raw = strings.TrimPrefix(line, "--- a/")
		default:
			continue
		}
		// Skip /dev/null (new or deleted files with no counterpart).
		if raw == "/dev/null" || raw == "" {
			continue
		}
		if !seen[raw] {
			seen[raw] = true
			out = append(out, raw)
		}
	}
	return out
}
