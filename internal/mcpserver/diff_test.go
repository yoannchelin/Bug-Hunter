package mcpserver

import "testing"

func TestPathsFromDiff(t *testing.T) {
	diff := `diff --git a/internal/store/store.go b/internal/store/store.go
index abc..def 100644
--- a/internal/store/store.go
+++ b/internal/store/store.go
@@ -1,3 +1,4 @@
 package store
+// added line
diff --git a/cmd/hunter/main.go b/cmd/hunter/main.go
index 111..222 100644
--- a/cmd/hunter/main.go
+++ b/cmd/hunter/main.go
@@ -5,6 +5,7 @@
 import "fmt"
+// new import
diff --git a/newfile.go b/newfile.go
new file mode 100644
--- /dev/null
+++ b/newfile.go
@@ -0,0 +1 @@
+package p
`
	paths := pathsFromDiff(diff)

	want := map[string]bool{
		"internal/store/store.go": true,
		"cmd/hunter/main.go":      true,
		"newfile.go":              true,
	}

	if len(paths) != len(want) {
		t.Fatalf("pathsFromDiff: got %v (len %d), want %d paths", paths, len(paths), len(want))
	}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected path: %q", p)
		}
	}
}

func TestPathsFromDiff_Dedup(t *testing.T) {
	// Same file appears in both --- and +++ lines — should appear once.
	diff := `--- a/foo.go
+++ b/foo.go
--- a/foo.go
+++ b/foo.go
`
	paths := pathsFromDiff(diff)
	if len(paths) != 1 {
		t.Errorf("expected 1 unique path, got %d: %v", len(paths), paths)
	}
}

func TestPathsFromDiff_DevNull(t *testing.T) {
	// Deleted file: +++ /dev/null should be ignored.
	diff := `--- a/deleted.go
+++ /dev/null
`
	paths := pathsFromDiff(diff)
	for _, p := range paths {
		if p == "/dev/null" {
			t.Error("/dev/null should be excluded from paths")
		}
	}
}

func TestPathsFromDiff_Empty(t *testing.T) {
	paths := pathsFromDiff("")
	if len(paths) != 0 {
		t.Errorf("empty diff: got %v, want none", paths)
	}
}
