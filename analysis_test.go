// PhishDetect
// Copyright (c) 2018-2019 Claudio Guarnieri.
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
	"testing"
)

func TestBrandDetection(t *testing.T) {
	domainsBrands := map[string]string{
		"yahoo":     "https://www.yahoo.com",
		"google":    "https://www.google.com",
		"microsoft": "https://www.onedrive.com",
		"amazon":    "http://www.amazon.co.jp",
	}

	for urlBrand, url := range domainsBrands {
		a := NewAnalysis(url, "")
		a.AnalyzeURL()
		brand := a.Brands.GetBrand()

		if brand != urlBrand {
			t.Errorf("Failed to identify brand, got \"%s\" expected \"%s\"", brand, urlBrand)
		}
	}
}

func TestDomainSafelist(t *testing.T) {
	domainsSafelist := map[string]bool{
		"https://www.yahoo.com":      true,
		"https://www.google.com":     true,
		"https://www.onedrive.com":   true,
		"http://www.amazon.co.jp":    true,
		"http://not-real-google.com": false,
	}

	for url, expectedSafelist := range domainsSafelist {
		a := NewAnalysis(url, "")
		a.AnalyzeURL()

		if a.Safelisted != expectedSafelist {
			t.Errorf("Failed to identify safelisted domain, got \"%v\" expected \"%v\"",
				a.Safelisted, expectedSafelist)
		}
	}
}

func TestDomainWarnings(t *testing.T) {
	url := "https://fake.gooogle.com-domain.xyz"
	expectedWarnings := []string{
		"suspicious-tld",
		"excessive-punct",
		"suspicious-hostname",
		"suspicious-bridges",
	}

	a := NewAnalysis(url, "")
	a.AnalyzeURL()

	counter := 0
	for _, warning := range a.Warnings {
		if SliceContains(expectedWarnings, warning.Name) {
			counter++
		}
	}

	if counter != len(expectedWarnings) {
		t.Errorf("Failed to test URL warnings, got \"%d\" expected \"%d\"",
			counter, len(expectedWarnings))
	}
}

func TestHTMLWarnings(t *testing.T) {
	url := "https://suspicious.domain"
	html := `<html>
<head>
<title>Google Sign-In</title>
</head>
<body>
<form method="POST" action="form.php">
	<input type="password" name="password" />
	<input type="hidden" name="hidden" value="hidden" />
	<input type="submit" value="Login" />
</form>
</body>
</html>`

	expectedWarnings := []string{
		"suspicious-title",
		"password-input",
		"hidden-input",
		"php-form",
	}

	a := NewAnalysis(url, html)
	a.AnalyzeHTML()

	counter := 0
	for _, warning := range a.Warnings {
		if SliceContains(expectedWarnings, warning.Name) {
			counter++
		}
	}

	if counter != len(expectedWarnings) {
		t.Errorf("Failed to test URL warnings, got \"%d\" expected \"%d\"",
			counter, len(expectedWarnings))
	}
}
