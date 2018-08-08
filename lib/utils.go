package phishdetect

import (
	"strings"
)

// TextContains will determine if a substring is present in a string.
// It is case-insensitive.
func TextContains(text, pattern string) bool {
	pattern = strings.ToLower(pattern)
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.ToLower(line)
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}

// SliceContains checks whether a string is contained in a slice of strings.
func SliceContains(slice []string, item string) bool {
	for _, entry := range slice {
		if item == entry {
			return true
		}
	}
	return false
}
