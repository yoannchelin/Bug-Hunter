package codeanalysis

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/leazelaya/bug-hunter/internal/store"
)

// SilentError is a detected error-handling issue in Go source.
type SilentError struct {
	Path    string
	Line    int
	Kind    string // "ignored_error", "swallowed_panic", "unguarded_goroutine", "lost_error"
	Message string
}

// AnalyzeRepo walks a repository root and returns all silent errors found in Go files.
func AnalyzeRepo(root string) ([]SilentError, error) {
	var results []SilentError
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if isGenerated(path) {
			return nil
		}
		errs, err := analyzeFile(path)
		if err != nil {
			return nil // skip unparseable files
		}
		results = append(results, errs...)
		return nil
	})
	return results, err
}

// isGenerated returns true if the file starts with the standard Go generated-file comment.
func isGenerated(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for i := 0; i < 5 && scanner.Scan(); i++ {
		if strings.Contains(scanner.Text(), "Code generated") {
			return true
		}
	}
	return false
}

func analyzeFile(path string) ([]SilentError, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}

	var out []SilentError

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {

		// err := f(); _ = err  or  _, err := f(); <err not used>
		case *ast.AssignStmt:
			if errs := checkAssignIgnoredErr(fset, path, node, f); len(errs) > 0 {
				out = append(out, errs...)
			}

		// recover() as a bare expression statement — result discarded, panic swallowed silently.
		case *ast.ExprStmt:
			if e := checkSwallowedPanic(fset, path, node); e != nil {
				out = append(out, *e)
			}

		// go func() { ... }() with no error handling
		case *ast.GoStmt:
			if e := checkUnguardedGoroutine(fset, path, node); e != nil {
				out = append(out, *e)
			}

		// if err != nil { return } with no wrapping or log
		case *ast.IfStmt:
			if e := checkLostError(fset, path, node); e != nil {
				out = append(out, *e)
			}
		}
		return true
	})

	return out, nil
}

// checkAssignIgnoredErr flags `_ = someCall()` where the entire call result is discarded.
// Does NOT flag `_, err := call()` patterns where at least one non-blank identifier exists.
func checkAssignIgnoredErr(fset *token.FileSet, path string, node *ast.AssignStmt, _ *ast.File) []SilentError {
	// Only flag when the RHS is a single call and ALL LHS are blank identifiers.
	if len(node.Rhs) != 1 {
		return nil
	}
	if _, isCall := node.Rhs[0].(*ast.CallExpr); !isCall {
		return nil
	}
	for _, lhs := range node.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" {
			return nil // at least one real binding — not fully discarded
		}
	}
	pos := fset.Position(node.Pos())
	return []SilentError{{
		Path:    path,
		Line:    pos.Line,
		Kind:    "ignored_error",
		Message: fmt.Sprintf("entire return value discarded with blank identifier at line %d", pos.Line),
	}}
}

// checkSwallowedPanic detects `recover()` used as a bare statement with no result capture.
// Patterns like `if r := recover(); r != nil { ... }` are NOT flagged.
func checkSwallowedPanic(fset *token.FileSet, path string, node *ast.ExprStmt) *SilentError {
	call, ok := node.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "recover" {
		return nil
	}
	pos := fset.Position(node.Pos())
	return &SilentError{
		Path:    path,
		Line:    pos.Line,
		Kind:    "swallowed_panic",
		Message: fmt.Sprintf("recover() result discarded at line %d — panic swallowed silently", pos.Line),
	}
}

// checkUnguardedGoroutine flags `go func() { ... }()` where errors from multiple
// calls are neither checked nor communicated back.
// Single-delegate goroutines (go func() { obj.Loop() }()) are excluded — the callee
// manages its own lifecycle.
func checkUnguardedGoroutine(fset *token.FileSet, path string, node *ast.GoStmt) *SilentError {
	funcLit, ok := node.Call.Fun.(*ast.FuncLit)
	if !ok {
		return nil
	}

	// Count direct call statements in the body (excluding defer).
	callStmts := 0
	for _, stmt := range funcLit.Body.List {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			if _, ok := s.X.(*ast.CallExpr); ok {
				callStmts++
			}
		case *ast.AssignStmt:
			callStmts++ // any assignment could capture an error
		case *ast.DeferStmt:
			// defer wg.Done() — not a business call, ignore.
		}
	}
	// A single-delegate goroutine is fine; only inspect multi-call bodies.
	if callStmts <= 1 {
		return nil
	}

	handled := false
	ast.Inspect(funcLit.Body, func(n ast.Node) bool {
		if handled {
			return false
		}
		switch x := n.(type) {
		case *ast.IfStmt:
			if isBinaryErrCheck(x.Cond) {
				handled = true
			}
		case *ast.SendStmt:
			handled = true
		case *ast.CallExpr:
			if isLogOrPanic(x) {
				handled = true
			}
		}
		return !handled
	})

	if !handled {
		pos := fset.Position(node.Pos())
		return &SilentError{
			Path:    path,
			Line:    pos.Line,
			Kind:    "unguarded_goroutine",
			Message: fmt.Sprintf("goroutine at line %d has no error handling inside", pos.Line),
		}
	}
	return nil
}

// isLogOrPanic returns true for calls like log.*, zap.*, panic, fmt.Fprintf(os.Stderr).
func isLogOrPanic(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "panic"
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		if !ok {
			return false
		}
		name := pkg.Name
		return name == "log" || name == "zap" || name == "logger" ||
			name == "slog" || name == "logrus" || name == "fmt" && fn.Sel.Name == "Fprintf"
	}
	return false
}

// checkLostError flags `if err != nil { return }` where err is NOT propagated.
// Patterns flagged:
//   - bare `return` (named return stays zero — err silently becomes nil)
//   - `return x, nil, ...` where no result is the err variable itself
//
// NOT flagged: `return nil, err` or `return fmt.Errorf(...)` — error is propagated.
func checkLostError(fset *token.FileSet, path string, node *ast.IfStmt) *SilentError {
	if !isBinaryErrCheck(node.Cond) {
		return nil
	}
	block := node.Body
	if block == nil || len(block.List) == 0 {
		return nil
	}
	if len(block.List) != 1 {
		return nil
	}
	ret, isReturn := block.List[0].(*ast.ReturnStmt)
	if !isReturn {
		return nil
	}
	// Bare return: err silently swallowed via named return.
	if len(ret.Results) == 0 {
		pos := fset.Position(node.Pos())
		return &SilentError{
			Path:    path,
			Line:    pos.Line,
			Kind:    "lost_error",
			Message: fmt.Sprintf("bare return inside err check — err swallowed via named return at line %d", pos.Line),
		}
	}
	// Check if any result propagates err (ident "err", or a call wrapping it).
	for _, r := range ret.Results {
		if propagatesErr(r) {
			return nil
		}
	}
	// None of the return values propagate err — it's silently dropped.
	pos := fset.Position(node.Pos())
	return &SilentError{
		Path:    path,
		Line:    pos.Line,
		Kind:    "lost_error",
		Message: fmt.Sprintf("error not propagated in return at line %d (returns without err)", pos.Line),
	}
}

// propagatesErr returns true when expr carries the err value forward.
func propagatesErr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "err"
	case *ast.CallExpr:
		// fmt.Errorf, errors.Wrap, etc. — any call is assumed to wrap err.
		return true
	case *ast.UnaryExpr:
		return propagatesErr(e.X)
	}
	return false
}

// isBinaryErrCheck returns true for `err != nil`.
func isBinaryErrCheck(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	left, ok := bin.X.(*ast.Ident)
	if !ok || left.Name != "err" {
		return false
	}
	right, ok := bin.Y.(*ast.Ident)
	return ok && right.Name == "nil"
}

// ToFindings converts SilentErrors to store.Finding rows given a path→fileID map.
func ToFindings(errs []SilentError, pathToID map[string]int64, blast map[int64]store.BlastMetric) []store.Finding {
	var out []store.Finding
	for _, e := range errs {
		// Normalize path to relative if possible.
		fileID := pathToID[e.Path]
		bm := blast[fileID]
		out = append(out, store.Finding{
			FileID:      fileID,
			Kind:        "silent_error",
			Severity:    "medium",
			Message:     e.Message,
			Path:        e.Path,
			Line:        e.Line,
			BlastRadius: bm.TransitiveIn,
			BlastRisk:   bm.RiskScore,
		})
	}
	return out
}
