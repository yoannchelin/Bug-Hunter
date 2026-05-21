package codeanalysis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AnalyzePyRepo walks a repository root and returns silent errors in Python files.
func AnalyzePyRepo(root string) ([]SilentError, error) {
	var results []SilentError
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "__pycache__" || name == ".venv" || name == "venv" ||
				name == "env" || name == ".tox" || name == "dist" || name == "build" ||
				strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".py" {
			return nil
		}
		if isGenerated(path) {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") ||
			base == "conftest.py" {
			return nil
		}

		errs, err := analyzePyFile(path)
		if err != nil {
			return nil
		}
		results = append(results, errs...)
		return nil
	})
	return results, err
}

func analyzePyFile(path string) ([]SilentError, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var out []SilentError
	out = append(out, detectBareExcept(path, lines)...)
	out = append(out, detectEmptyExcept(path, lines)...)
	out = append(out, detectUncheckedSubprocess(path, lines)...)
	return out, nil
}

// detectBareExcept finds `except:` with no exception type — catches everything
// including KeyboardInterrupt and SystemExit, which is almost always a bug.
func detectBareExcept(path string, lines []string) []SilentError {
	var out []SilentError
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "except:" || trimmed == "except :" {
			out = append(out, SilentError{
				Path:    path,
				Line:    i + 1,
				Kind:    "swallowed_exception",
				Message: fmt.Sprintf("bare except: at line %d — catches KeyboardInterrupt and SystemExit, almost always a bug", i+1),
			})
		}
	}
	return out
}

// detectEmptyExcept finds except blocks whose body is only `pass` or a comment.
// Covers: `except Exception:`, `except (TypeError, ValueError):`, etc.
func detectEmptyExcept(path string, lines []string) []SilentError {
	var out []SilentError
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "except") {
			continue
		}
		// Must end with ':' (possibly after exception types).
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}
		// Skip bare `except:` — handled by detectBareExcept.
		if trimmed == "except:" || trimmed == "except :" {
			continue
		}
		// Look at the next non-blank, non-comment line.
		body := exceptBody(lines, i+1)
		if body == "pass" || body == "" {
			out = append(out, SilentError{
				Path:    path,
				Line:    i + 1,
				Kind:    "swallowed_exception",
				Message: fmt.Sprintf("empty except block at line %d — exception swallowed silently", i+1),
			})
		}
	}
	return out
}

// exceptBody returns the stripped content of the first meaningful line of a Python block
// starting at lineIdx. Returns "" if the block is empty/comment-only.
func exceptBody(lines []string, lineIdx int) string {
	for j := lineIdx; j < len(lines) && j < lineIdx+10; j++ {
		t := strings.TrimSpace(lines[j])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t
	}
	return ""
}

// detectUncheckedSubprocess finds subprocess calls without check=True or a try/catch wrapper.
// subprocess.run/call/Popen without check=True silently ignore non-zero exit codes.
func detectUncheckedSubprocess(path string, lines []string) []SilentError {
	var out []SilentError
	inTry := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track try block depth (rough heuristic).
		if trimmed == "try:" {
			inTry++
		}
		if inTry > 0 && strings.HasPrefix(trimmed, "except") {
			inTry--
		}

		if !strings.Contains(trimmed, "subprocess.") {
			continue
		}
		// Only flag run/call — Popen is lower-level and often used intentionally.
		if !strings.Contains(trimmed, "subprocess.run(") && !strings.Contains(trimmed, "subprocess.call(") {
			continue
		}
		if strings.Contains(trimmed, "#") {
			continue // skip commented-out lines
		}
		if inTry > 0 {
			continue // wrapped in try — error is (possibly) handled
		}
		if strings.Contains(trimmed, "check=True") || strings.Contains(trimmed, "check = True") {
			continue // caller opted into exception on failure
		}
		out = append(out, SilentError{
			Path:    path,
			Line:    i + 1,
			Kind:    "swallowed_exception",
			Message: fmt.Sprintf("subprocess.run/call without check=True at line %d — non-zero exit silently ignored", i+1),
		})
	}
	return out
}
