package codeanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTSFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.ts")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	return f.Name()
}

// ---- swallowed_exception ----

func TestTS_EmptyCatch_Detected(t *testing.T) {
	src := `
async function doWork() {
  try {
    await riskyCall();
  } catch (e) {
  }
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for empty catch block, got none")
	}
}

func TestTS_EmptyCatch_CommentOnly(t *testing.T) {
	src := `
function f() {
  try {
    doSomething();
  } catch (e) {
    // intentionally ignored
  }
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for comment-only catch block, got none")
	}
}

func TestTS_EmptyCatch_NotFlaggedWhenHandled(t *testing.T) {
	src := `
async function doWork() {
  try {
    await riskyCall();
  } catch (e) {
    console.error('failed:', e);
    throw e;
  }
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf("catch with error handling should not be flagged; got %v", got)
	}
}

func TestTS_EmptyPromiseCatch_Detected(t *testing.T) {
	src := `
fetch('/api/data')
  .then(res => res.json())
  .catch(() => {});
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for empty .catch(() => {}), got none")
	}
}

func TestTS_EmptyPromiseCatch_WithUnderscore(t *testing.T) {
	src := `
somePromise().catch(_ => {});
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for .catch(_ => {}), got none")
	}
}

func TestTS_EmptyPromiseCatch_NotFlaggedWhenHandled(t *testing.T) {
	src := `
fetch('/api')
  .then(res => res.json())
  .catch(err => {
    console.error(err);
  });
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf(".catch with body should not be flagged; got %v", got)
	}
}

// ---- floating_promise ----

func TestTS_FloatingPromise_Detected(t *testing.T) {
	src := `
async function handler() {
  doSomethingAsync();
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "floating_promise"); len(got) == 0 {
		t.Error("expected floating_promise for unawaited call in async func, got none")
	}
}

func TestTS_FloatingPromise_NotFlaggedWithAwait(t *testing.T) {
	src := `
async function handler() {
  await doSomethingAsync();
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "floating_promise"); len(got) > 0 {
		t.Errorf("awaited call should not be flagged; got %v", got)
	}
}

func TestTS_FloatingPromise_NotFlaggedWithCatch(t *testing.T) {
	src := `
async function handler() {
  doSomethingAsync()
    .catch(err => console.error(err));
}
`
	errs, err := analyzeTSFile(writeTSFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "floating_promise"); len(got) > 0 {
		t.Errorf("chained .catch should not be flagged; got %v", got)
	}
}

// ---- AnalyzeTSRepo filters ----

func TestAnalyzeTSRepo_Filters(t *testing.T) {
	dir := t.TempDir()

	// Declaration file — skip.
	os.WriteFile(filepath.Join(dir, "types.d.ts"),
		[]byte("declare function f(): Promise<void>;\n"), 0o644)

	// Test file — skip.
	os.WriteFile(filepath.Join(dir, "foo.test.ts"),
		[]byte("it('test', async () => { doAsync(); });\n"), 0o644)

	// node_modules — skip entire dir.
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.ts"),
		[]byte("export function f() { try {} catch(e) {} }\n"), 0o644)

	// Real file with empty catch.
	os.WriteFile(filepath.Join(dir, "main.ts"), []byte(`
async function run() {
  try {
    await doWork();
  } catch (e) {
  }
}
`), 0o644)

	errs, err := AnalyzeTSRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range errs {
		base := filepath.Base(e.Path)
		if base == "types.d.ts" || base == "foo.test.ts" {
			t.Errorf("should not have analysed %s", base)
		}
		if strings.Contains(e.Path, "node_modules") {
			t.Errorf("should not have analysed node_modules file: %s", e.Path)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least 1 finding in main.ts")
	}
}
