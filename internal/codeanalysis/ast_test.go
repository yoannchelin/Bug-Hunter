package codeanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes content to a temp file and returns its path.
func writeFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func findKind(errs []SilentError, kind string) []SilentError {
	var out []SilentError
	for _, e := range errs {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// ---- ignored_error ----

func TestIgnoredError_Detected(t *testing.T) {
	src := `package p
import "os"
func f() {
	_ = os.Remove("/tmp/x")
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "ignored_error"); len(got) == 0 {
		t.Error("expected ignored_error for _ = os.Remove(), got none")
	}
}

func TestIgnoredError_NotFlaggedPartialBlank(t *testing.T) {
	// _, err := f() should NOT be flagged — err is captured.
	src := `package p
import "os"
func f() error {
	_, err := os.Open("/tmp/x")
	if err != nil {
		return err
	}
	return nil
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "ignored_error"); len(got) > 0 {
		t.Errorf("_, err := call() should not be flagged; got %v", got)
	}
}

// ---- swallowed_panic ----

func TestSwallowedPanic_Detected(t *testing.T) {
	// Bare recover() as an expression statement — result discarded.
	src := `package p
func f() {
	defer func() {
		recover()
	}()
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_panic"); len(got) == 0 {
		t.Error("expected swallowed_panic for bare recover(), got none")
	}
}

func TestSwallowedPanic_NotFlaggedWhenCaptured(t *testing.T) {
	// if r := recover(); r != nil { ... } should NOT be flagged.
	src := `package p
import "log"
func f() {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r)
		}
	}()
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_panic"); len(got) > 0 {
		t.Errorf("recover() captured in if-init should not be flagged; got %v", got)
	}
}

// ---- lost_error ----

func TestLostError_BareReturn(t *testing.T) {
	// Named return: bare `return` inside `if err != nil` swallows the error.
	src := `package p
func f() (result string, err error) {
	result, err = g()
	if err != nil {
		return
	}
	return result, nil
}
func g() (string, error) { return "", nil }
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "lost_error"); len(got) == 0 {
		t.Error("expected lost_error for bare return in named-return func, got none")
	}
}

func TestLostError_ReturnNilDropsErr(t *testing.T) {
	// if err != nil { return nil, nil } — err not propagated.
	src := `package p
func f() ([]byte, error) {
	b, err := g()
	if err != nil {
		return nil, nil
	}
	return b, nil
}
func g() ([]byte, error) { return nil, nil }
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "lost_error"); len(got) == 0 {
		t.Error("expected lost_error for return nil, nil inside err check, got none")
	}
}

func TestLostError_NotFlaggedWhenPropagated(t *testing.T) {
	// if err != nil { return nil, err } — error IS propagated, should not flag.
	src := `package p
func f() ([]byte, error) {
	b, err := g()
	if err != nil {
		return nil, err
	}
	return b, nil
}
func g() ([]byte, error) { return nil, nil }
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "lost_error"); len(got) > 0 {
		t.Errorf("return nil, err should not be flagged; got %v", got)
	}
}

func TestLostError_NotFlaggedWhenWrapped(t *testing.T) {
	// if err != nil { return nil, fmt.Errorf(...) } — wrapped, should not flag.
	src := `package p
import "fmt"
func f() ([]byte, error) {
	b, err := g()
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}
	return b, nil
}
func g() ([]byte, error) { return nil, nil }
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "lost_error"); len(got) > 0 {
		t.Errorf("fmt.Errorf wrap should not be flagged; got %v", got)
	}
}

// ---- unguarded_goroutine ----

func TestUnguardedGoroutine_Detected(t *testing.T) {
	// Multi-call goroutine with no error handling.
	src := `package p
import "os"
func f() {
	go func() {
		os.Remove("/tmp/a")
		os.Remove("/tmp/b")
	}()
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "unguarded_goroutine"); len(got) == 0 {
		t.Error("expected unguarded_goroutine for multi-call goroutine with no err check, got none")
	}
}

func TestUnguardedGoroutine_NotFlaggedSingleDelegate(t *testing.T) {
	// Single-delegate goroutine — callee manages its own lifecycle.
	src := `package p
func loop() {}
func f() {
	go func() {
		loop()
	}()
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "unguarded_goroutine"); len(got) > 0 {
		t.Errorf("single-delegate goroutine should not be flagged; got %v", got)
	}
}

func TestUnguardedGoroutine_NotFlaggedWithChannel(t *testing.T) {
	// Goroutine sends result to channel — error communicated to caller.
	src := `package p
func work() error { return nil }
func f() {
	errc := make(chan error, 1)
	go func() {
		errc <- work()
	}()
	_ = <-errc
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "unguarded_goroutine"); len(got) > 0 {
		t.Errorf("goroutine with channel send should not be flagged; got %v", got)
	}
}

func TestUnguardedGoroutine_NotFlaggedWithErrCheck(t *testing.T) {
	src := `package p
import "log"
func work() error { return nil }
func f() {
	go func() {
		if err := work(); err != nil {
			log.Println(err)
		}
		if err := work(); err != nil {
			log.Println(err)
		}
	}()
}
`
	errs, err := analyzeFile(writeFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "unguarded_goroutine"); len(got) > 0 {
		t.Errorf("goroutine with err checks should not be flagged; got %v", got)
	}
}

// ---- isGenerated ----

func TestIsGenerated(t *testing.T) {
	dir := t.TempDir()

	gen := filepath.Join(dir, "gen.go")
	os.WriteFile(gen, []byte("// Code generated by protoc. DO NOT EDIT.\npackage p\n"), 0o644)

	normal := filepath.Join(dir, "normal.go")
	os.WriteFile(normal, []byte("// Package p does things.\npackage p\n"), 0o644)

	if !isGenerated(gen) {
		t.Error("generated file not detected")
	}
	if isGenerated(normal) {
		t.Error("normal file incorrectly marked as generated")
	}
}

// ---- AnalyzeRepo skips test and generated files ----

func TestAnalyzeRepo_Filters(t *testing.T) {
	dir := t.TempDir()

	// Generated file — should be skipped entirely.
	os.WriteFile(filepath.Join(dir, "gen.go"),
		[]byte("// Code generated by x. DO NOT EDIT.\npackage p\nfunc f() { _ = g() }\nfunc g() error { return nil }\n"), 0o644)

	// Test file — should be skipped.
	os.WriteFile(filepath.Join(dir, "foo_test.go"),
		[]byte("package p\nfunc TestFoo(t interface{}) { _ = g() }\nfunc g() error { return nil }\n"), 0o644)

	// Real file with an ignored error.
	os.WriteFile(filepath.Join(dir, "real.go"),
		[]byte("package p\nimport \"os\"\nfunc h() { _ = os.Remove(\"/x\") }\n"), 0o644)

	errs, err := AnalyzeRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range errs {
		base := filepath.Base(e.Path)
		if base == "gen.go" || base == "foo_test.go" {
			t.Errorf("should not have analysed %s", base)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least 1 finding in real.go")
	}
}

// ---- ToFindings kind/severity mapping ----

func TestToFindings_KindAndSeverity(t *testing.T) {
	pathToID := map[string]int64{"a.ts": 1}

	cases := []struct {
		kind       string
		wantDBKind string
		wantSev    string
	}{
		{"swallowed_exception", "silent_error", "high"},
		{"swallowed_panic", "silent_error", "high"},
		{"ignored_error", "silent_error", "medium"},
		{"lost_error", "silent_error", "medium"},
		{"unguarded_goroutine", "silent_error", "medium"},
		{"floating_promise", "silent_error", "low"},
		{"unsafe_assertion", "unsafe_assertion", "low"},
	}

	for _, tc := range cases {
		errs := []SilentError{{Path: "a.ts", Line: 1, Kind: tc.kind, Message: "test"}}
		fds := ToFindings(errs, pathToID, nil)
		if len(fds) != 1 {
			t.Errorf("kind %s: got %d findings, want 1", tc.kind, len(fds))
			continue
		}
		if fds[0].Kind != tc.wantDBKind {
			t.Errorf("kind %s: DB kind = %q, want %q", tc.kind, fds[0].Kind, tc.wantDBKind)
		}
		if fds[0].Severity != tc.wantSev {
			t.Errorf("kind %s: severity = %q, want %q", tc.kind, fds[0].Severity, tc.wantSev)
		}
	}
}

func TestToFindings_BlastPromotesSeverity(t *testing.T) {
	if kindToSeverity("floating_promise") != "low" {
		t.Error("floating_promise base severity should be low")
	}
	if promoteSeverity("low") != "medium" {
		t.Error("promoteSeverity(low) should be medium")
	}
	if promoteSeverity("medium") != "high" {
		t.Error("promoteSeverity(medium) should be high")
	}
	if promoteSeverity("high") != "high" {
		t.Error("promoteSeverity(high) should stay high")
	}
}
