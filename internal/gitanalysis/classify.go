package gitanalysis

import "strings"

// fixKeywords are the lower-case tokens that mark a commit as a bugfix.
var fixKeywords = []string{
	"fix", "bug", "hotfix", "patch", "regression", "revert",
	"issue", "error", "broken", "crash", "panic",
}

// mergeKeywords identify merge commits by subject when num_parents is unavailable.
var mergeKeywords = []string{"merge ", "merge pull request", "merge branch"}

// IsFixCommit returns true when the commit message looks like a bugfix.
func IsFixCommit(message string) bool {
	low := strings.ToLower(message)
	for _, kw := range fixKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// IsMergeCommit returns true when the subject looks like an auto-generated merge commit.
func IsMergeCommit(subject string) bool {
	low := strings.ToLower(subject)
	for _, kw := range mergeKeywords {
		if strings.HasPrefix(low, kw) {
			return true
		}
	}
	return false
}
