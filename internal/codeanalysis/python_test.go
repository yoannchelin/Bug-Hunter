package codeanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePyFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.py")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	return f.Name()
}

// ---- bare except ----

func TestPy_BareExcept_Detected(t *testing.T) {
	src := `
def load(path):
    try:
        return open(path).read()
    except:
        pass
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for bare except:, got none")
	}
}

func TestPy_BareExcept_NotFlaggedWhenHandled(t *testing.T) {
	src := `
def load(path):
    try:
        return open(path).read()
    except IOError as e:
        print(f"error: {e}")
        raise
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf("handled except should not be flagged; got %v", got)
	}
}

// ---- empty except ----

func TestPy_EmptyExcept_WithPass(t *testing.T) {
	src := `
def parse(data):
    try:
        return int(data)
    except ValueError:
        pass
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for except ValueError: pass, got none")
	}
}

func TestPy_EmptyExcept_NotFlaggedWithBody(t *testing.T) {
	src := `
def parse(data):
    try:
        return int(data)
    except ValueError as e:
        logger.warning("bad input: %s", e)
        return 0
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf("except with body should not be flagged; got %v", got)
	}
}

func TestPy_EmptyExcept_CommentOnly(t *testing.T) {
	src := `
def run():
    try:
        do_work()
    except Exception:
        # intentionally ignored
        pass
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for comment+pass except block, got none")
	}
}

// ---- subprocess without check=True ----

func TestPy_Subprocess_UncheckedRun(t *testing.T) {
	src := `
import subprocess

def build():
    subprocess.run(["make", "all"])
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) == 0 {
		t.Error("expected swallowed_exception for subprocess.run without check=True, got none")
	}
}

func TestPy_Subprocess_CheckedRun_NotFlagged(t *testing.T) {
	src := `
import subprocess

def build():
    subprocess.run(["make", "all"], check=True)
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf("subprocess.run with check=True should not be flagged; got %v", got)
	}
}

func TestPy_Subprocess_InTryBlock_NotFlagged(t *testing.T) {
	src := `
import subprocess

def build():
    try:
        subprocess.run(["make", "all"])
    except subprocess.CalledProcessError as e:
        print(f"build failed: {e}")
`
	errs, err := analyzePyFile(writePyFile(t, src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findKind(errs, "swallowed_exception"); len(got) > 0 {
		t.Errorf("subprocess.run in try block should not be flagged; got %v", got)
	}
}

// ---- AnalyzePyRepo filters ----

func TestAnalyzePyRepo_Filters(t *testing.T) {
	dir := t.TempDir()

	// Test file — skip.
	os.WriteFile(filepath.Join(dir, "test_api.py"), []byte(`
def test_foo():
    try:
        pass
    except:
        pass
`), 0o644)

	// __pycache__ dir — skip.
	os.MkdirAll(filepath.Join(dir, "__pycache__"), 0o755)
	os.WriteFile(filepath.Join(dir, "__pycache__", "utils.py"), []byte(`
def f():
    try:
        pass
    except:
        pass
`), 0o644)

	// Real file with bare except.
	os.WriteFile(filepath.Join(dir, "utils.py"), []byte(`
def load(p):
    try:
        return open(p).read()
    except:
        pass
`), 0o644)

	errs, err := AnalyzePyRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range errs {
		base := filepath.Base(e.Path)
		if base == "test_api.py" {
			t.Errorf("should not have analysed test file: %s", e.Path)
		}
		if strings.Contains(e.Path, "__pycache__") {
			t.Errorf("should not have analysed __pycache__ file: %s", e.Path)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least 1 finding in utils.py")
	}
}
