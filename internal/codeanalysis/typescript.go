package codeanalysis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AnalyzeTSRepo walks a repository root and returns silent errors in TypeScript files.
func AnalyzeTSRepo(root string) ([]SilentError, error) {
	var results []SilentError
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "dist" || name == "build" ||
				name == ".next" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".ts" && ext != ".tsx" && ext != ".js" && ext != ".jsx" {
			return nil
		}
		if strings.HasSuffix(path, ".d.ts") {
			return nil // skip declaration files
		}
		if isGenerated(path) {
			return nil
		}
		if strings.HasSuffix(path, ".test.ts") || strings.HasSuffix(path, ".test.tsx") ||
			strings.HasSuffix(path, ".spec.ts") || strings.HasSuffix(path, ".spec.tsx") ||
			strings.HasSuffix(path, ".test.js") || strings.HasSuffix(path, ".spec.js") {
			return nil
		}

		errs, err := analyzeTSFile(path)
		if err != nil {
			return nil
		}
		results = append(results, errs...)
		return nil
	})
	return results, err
}

func analyzeTSFile(path string) ([]SilentError, error) {
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
	out = append(out, detectEmptyCatch(path, lines)...)
	out = append(out, detectEmptyPromiseCatch(path, lines)...)
	out = append(out, detectFloatingPromise(path, lines)...)
	out = append(out, detectUnsafeJSONParse(path, lines)...)
	out = append(out, detectNonNullAssertion(path, lines)...)
	return out, nil
}

// detectEmptyCatch finds `catch` blocks that contain no statements.
// Matches: catch (e) { } or catch { } with only whitespace/comments inside.
func detectEmptyCatch(path string, lines []string) []SilentError {
	var out []SilentError
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "catch") {
			continue
		}
		// Find the opening brace of the catch body — it must come AFTER "catch" on this line
		// or on the very next line. We skip any braces that appear before "catch".
		catchIdx := strings.Index(trimmed, "catch")
		afterCatch := trimmed[catchIdx:]

		openLine := -1
		if strings.Contains(afterCatch, "{") {
			openLine = i
		} else if i+1 < len(lines) && strings.Contains(strings.TrimSpace(lines[i+1]), "{") {
			openLine = i + 1
		}
		if openLine < 0 {
			continue
		}

		// Extract body starting from the first '{' AFTER the catch keyword.
		body := extractCatchBody(lines, openLine, catchIdx)
		if body == "" {
			continue
		}
		stripped := stripComments(body)
		if strings.TrimSpace(stripped) == "" {
			out = append(out, SilentError{
				Path:    path,
				Line:    i + 1,
				Kind:    "swallowed_exception",
				Message: fmt.Sprintf("empty catch block at line %d — exception swallowed silently", i+1),
			})
		}
	}
	return out
}

// extractCatchBody extracts the catch body starting from the first '{' after the catch keyword on startLine.
func extractCatchBody(lines []string, startLine, _ int) string {
	depth := 0
	var body strings.Builder
	started := false
	skipUntilCatch := true

	for i := startLine; i < len(lines) && i < startLine+20; i++ {
		lineContent := lines[i]
		startCol := 0
		if i == startLine && skipUntilCatch {
			// On the catch line, skip chars before (and including) the catch keyword area.
			catchPos := strings.Index(lineContent, "catch")
			if catchPos >= 0 {
				startCol = catchPos
			}
			skipUntilCatch = false
		}
		for _, ch := range lineContent[startCol:] {
			if ch == '{' {
				if depth == 0 {
					started = true
					depth++
					continue
				}
				depth++
			} else if ch == '}' {
				if depth == 1 && started {
					return body.String()
				}
				depth--
			}
			if started && depth > 0 {
				body.WriteRune(ch)
			}
		}
		if started {
			body.WriteByte('\n')
		}
	}
	return ""
}

// detectEmptyPromiseCatch finds `.catch(() => {})` or `.catch(_ => {})` with empty body.
func detectEmptyPromiseCatch(path string, lines []string) []SilentError {
	var out []SilentError
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ".catch(") {
			continue
		}
		// Heuristic: .catch with an arrow function whose body is empty braces.
		// Matches: .catch(() => {}) .catch(_ => {}) .catch((_e) => {}) .catch(err => {})
		if matchesEmptyCatchHandler(trimmed) {
			out = append(out, SilentError{
				Path:    path,
				Line:    i + 1,
				Kind:    "swallowed_exception",
				Message: fmt.Sprintf("empty .catch() handler at line %d — promise rejection swallowed", i+1),
			})
		}
	}
	return out
}

// detectFloatingPromise finds async function calls that are not awaited
// and have no .then()/.catch() chained — a fire-and-forget without error handling.
func detectFloatingPromise(path string, lines []string) []SilentError {
	var out []SilentError
	inAsync := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track whether we're inside an async function.
		if strings.Contains(trimmed, "async function") || strings.Contains(trimmed, "async (") ||
			strings.Contains(trimmed, "async(") || strings.Contains(trimmed, "async =>") {
			inAsync = true
		}
		if !inAsync {
			continue
		}

		// A floating promise: statement starts with an identifier/call that is NOT
		// preceded by await, assignment, return, or yield, and ends without chaining.
		// Simple heuristic: line is an expression statement that calls a known async pattern.
		if isFloatingAsyncCall(trimmed, i, lines) {
			out = append(out, SilentError{
				Path:    path,
				Line:    i + 1,
				Kind:    "floating_promise",
				Message: fmt.Sprintf("floating promise at line %d — async call not awaited and not chained", i+1),
			})
		}
	}
	return out
}

// isFloatingAsyncCall returns true for lines that look like an unawaited async expression statement.
func isFloatingAsyncCall(line string, lineIdx int, lines []string) bool {
	// Must be a statement (ends with ';' or next line has no continuation).
	if !strings.HasSuffix(line, ";") && !strings.HasSuffix(line, ")") {
		return false
	}
	// Must not be preceded by await, assignment, return, yield, throw.
	lower := strings.ToLower(line)
	for _, kw := range []string{"await ", "return ", "yield ", "throw ", "= ", "const ", "let ", "var "} {
		if strings.Contains(lower, kw) {
			return false
		}
	}
	// Must not already chain .then or .catch.
	if strings.Contains(line, ".then(") || strings.Contains(line, ".catch(") {
		return false
	}
	// Must not be a declaration, import, comment, or control flow.
	for _, kw := range []string{"//", "if ", "for ", "while ", "switch ", "import ", "export ", "class ", "interface ", "type "} {
		if strings.HasPrefix(line, kw) {
			return false
		}
	}
	// Check the next line doesn't chain onto this one.
	if lineIdx+1 < len(lines) {
		next := strings.TrimSpace(lines[lineIdx+1])
		if strings.HasPrefix(next, ".then") || strings.HasPrefix(next, ".catch") || strings.HasPrefix(next, ".finally") {
			return false
		}
	}
	// Must contain a function call.
	return strings.Contains(line, "(") && strings.Contains(line, ")")
}

// detectUnsafeJSONParse finds JSON.parse() calls that are not inside a try block.
// These throw SyntaxError on invalid input and are a common source of uncaught exceptions.
func detectUnsafeJSONParse(path string, lines []string) []SilentError {
	var out []SilentError
	inTry := 0 // nesting depth inside try blocks
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Track try block entry/exit (rough brace counting per line).
		if strings.HasPrefix(trimmed, "try ") || trimmed == "try{" || strings.HasPrefix(trimmed, "try{") {
			inTry++
		}
		// A closing brace followed by "catch" on the same or next line closes the try scope.
		if inTry > 0 && strings.Contains(trimmed, "} catch") {
			inTry--
		}
		if inTry > 0 {
			continue
		}
		if !strings.Contains(trimmed, "JSON.parse(") {
			continue
		}
		// Skip if already inside a catch parameter (e.g. catch (e) { JSON.parse })
		// which would be caught by detectEmptyCatch separately.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		out = append(out, SilentError{
			Path:    path,
			Line:    i + 1,
			Kind:    "swallowed_exception",
			Message: fmt.Sprintf("JSON.parse() without try-catch at line %d — throws SyntaxError on invalid input", i+1),
		})
	}
	return out
}

// detectNonNullAssertion finds TypeScript non-null assertion operator `!` on property/method access.
// These bypass TypeScript's null safety and cause runtime crashes on null/undefined.
func detectNonNullAssertion(path string, lines []string) []SilentError {
	var out []SilentError
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments, imports, type declarations.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "export type ") ||
			strings.HasPrefix(trimmed, "type ") || strings.HasPrefix(trimmed, "interface ") {
			continue
		}
		// Only flag non-null assertion on member access: `foo!.bar` or `foo!()`.
		// Avoid false positives on !== comparisons, !=, logical !, regex.
		if !strings.Contains(trimmed, "!.") && !strings.Contains(trimmed, "!()") && !strings.Contains(trimmed, "![") {
			continue
		}
		// Skip test assertions like expect(x).not. or assert.notEqual
		if strings.Contains(trimmed, "expect(") || strings.Contains(trimmed, "assert") {
			continue
		}
		out = append(out, SilentError{
			Path:    path,
			Line:    i + 1,
			Kind:    "unsafe_assertion",
			Message: fmt.Sprintf("non-null assertion (!) at line %d — bypasses null safety, causes runtime crash on null/undefined", i+1),
		})
	}
	return out
}

// matchesEmptyCatchHandler returns true for `.catch(x => {})` variants with empty body.
func matchesEmptyCatchHandler(line string) bool {
	idx := strings.Index(line, ".catch(")
	if idx < 0 {
		return false
	}
	rest := line[idx+7:] // after ".catch("
	// Skip parameter: anything up to =>
	arrowIdx := strings.Index(rest, "=>")
	if arrowIdx < 0 {
		// Could be .catch(function() {}) — check for empty function body.
		if strings.Contains(rest, "function") {
			bodyIdx := strings.Index(rest, "{")
			closeIdx := strings.Index(rest, "}")
			if bodyIdx >= 0 && closeIdx > bodyIdx {
				inner := strings.TrimSpace(rest[bodyIdx+1 : closeIdx])
				return inner == ""
			}
		}
		return false
	}
	afterArrow := strings.TrimSpace(rest[arrowIdx+2:])
	if strings.HasPrefix(afterArrow, "{") {
		closeIdx := strings.Index(afterArrow, "}")
		if closeIdx < 0 {
			return false
		}
		inner := strings.TrimSpace(afterArrow[1:closeIdx])
		return inner == ""
	}
	return false
}

// stripComments removes single-line // comments from a string.
func stripComments(s string) string {
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}
