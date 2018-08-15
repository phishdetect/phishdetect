// PhishDetect
// Copyright (C) 2018  Claudio Guarnieri
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package phishdetect

import (
	"github.com/goware/urlx"
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
		if TextContains(item, entry) {
			return true
		}
	}

	return false
}

// NormalizeURL fixes a URL that is e.g. missing a scheme, etc.
func NormalizeURL(url string) string {
	url = strings.TrimSpace(url)
	cleanURL, _ := urlx.Parse(url)
	normalized, _ := urlx.Normalize(cleanURL)
	if normalized == "" {
		normalized = url
	}

	return normalized
}
