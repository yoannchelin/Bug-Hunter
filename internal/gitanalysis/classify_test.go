package gitanalysis

import "testing"

func TestIsFixCommit(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"fix: resolve nil pointer", true},
		{"bug: wrong offset calculation", true},
		{"hotfix auth regression", true},
		{"patch: memory leak in handler", true},
		{"revert bad merge", true},
		{"fix(auth): token expiry issue #42", true},
		{"Fix: capitalised keyword", true},
		{"feat: add pagination", false},
		{"refactor: extract helper", false},
		{"docs: update README", false},
		{"chore: bump dependencies", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsFixCommit(c.msg)
		if got != c.want {
			t.Errorf("IsFixCommit(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestIsMergeCommit(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"Merge pull request #123 from user/branch", true},
		{"merge branch 'main' into feature", true},
		{"Merge fix/auth-bug into main", true},
		{"fix: merge conflict resolved", false},
		{"feat: merge sort implementation", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsMergeCommit(c.msg)
		if got != c.want {
			t.Errorf("IsMergeCommit(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}
