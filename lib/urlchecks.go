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
	"encoding/base64"
	"regexp"
	"strings"
)

func checkSuspiciousHostname(link *Link, page *Page, brands *Brands) bool {
	lowSuspects := []string{
		"auth", "authorize", "authenticate", "authentication",
		"account", "myaccount",
		"activation",
		"apps",
		"confirm",
		"credential",
		"drive",
		"login",
		"mails", "rnail",
		"managment",
		"password",
		"permission", "permision",
		"recovery", "recover",
		"register",
		"secure", "safe",
		"signin",
		"support", "suport",
		"unlock",
		"update",
		"verify", "verification", "everivcation", "verifications", "veryfication", "veryfications",
		"wallet",
	}

	normalized := strings.Replace(link.Domain, ".", "|", -1)
	normalized = strings.Replace(normalized, "-", "|", -1)
	words := strings.Split(normalized, "|")

	high := 0
	low := 0

	for _, word := range words {
		for _, brand := range brands.List {
			if SliceContains(brand.Suspicious, word) {
				brand.Matches++
				return true
			} else if SliceContains(brand.Original, word) {
				brand.Matches++
				high++
			}
		}

		if SliceContains(lowSuspects, word) {
			low++
		}
	}

	if high >= 2 || (high >= 1 && low >= 1) || low >= 2 {
		return true
	}

	return false
}

func checkSuspiciousTLD(link *Link, page *Page, brands *Brands) bool {
	suspects := []string{".ga", ".gq", ".ml", ".cf", ".tk", ".xyz", "cc", ".gb",
		".info", ".biz", ".cm", ".online", ".support", ".click"}

	for _, suspect := range suspects {
		if strings.HasSuffix(link.Domain, suspect) {
			return true
		}
	}

	return false
}

func checkSuspiciousBridges(link *Link, page *Page, brands *Brands) bool {
	suspects := []string{".com-"}

	for _, suspect := range suspects {
		if strings.Contains(link.Domain, suspect) {
			return true
		}
	}

	return false
}

func checkEncodedDomain(link *Link, page *Page, brands *Brands) bool {
	if !strings.Contains(link.Domain, "xn--") {
		return false
	}

	for _, brand := range brands.List {
		for _, word := range brand.Suspicious {
			if !strings.Contains(word, "xn--") {
				continue
			}

			if strings.Contains(link.Domain, word) {
				brand.Matches++
				return true
			}
		}
	}

	return false
}

func checkExcessivePunct(link *Link, page *Page, brands *Brands) bool {
	regex, _ := regexp.Compile("\\.")
	dots := regex.FindAllString(link.Domain, -1)
	dotsCount := len(dots)

	dashesCount := 0
	if !strings.Contains(link.Domain, "xn--") {
		regex, _ = regexp.Compile("-")
		dashes := regex.FindAllString(link.Domain, -1)
		dashesCount = len(dashes)
	}

	total := dotsCount + dashesCount
	if total >= 4 {
		return true
	}

	return false
}

func checkNoTLS(link *Link, page *Page, brands *Brands) bool {
	if strings.HasPrefix(link.Scheme, "http") {
		if link.Scheme != "https" {
			return true
		}
	}

	return false
}

func checkB64Parameters(link *Link, page *Page, brands *Brands) bool {
	for _, value := range link.Parameters {
		// We skip strings that are too short, because they could significantly
		// raise false positives.
		if len(value) <= 5 {
			continue
		}
		_, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return true
		}
	}

	return false
}

// GetURLChecks returns a list of all the available URL checks.
func GetURLChecks() []Check {
	return []Check{
		Check{
			checkSuspiciousHostname,
			30,
			"suspicious-hostname",
			"The domain contains suspicious words",
		},
		Check{
			checkSuspiciousTLD,
			5,
			"suspicious-tld",
			"The domain uses a suspicious TLD",
		},
		Check{
			checkSuspiciousBridges,
			30,
			"suspicious-bridges",
			"The domain uses very suspicious patterns used for bad domains composition",
		},
		Check{
			checkEncodedDomain,
			50,
			"encoded-domain",
			"The domain contains special characters to mimic known brands",
		},
		Check{
			checkExcessivePunct,
			20,
			"excessive-punct",
			"The domain has suspicious amount of dots and dashes",
		},
		Check{
			checkNoTLS,
			20,
			"no-tls",
			"The website is not using a secure transport layer (HTTPS)",
		},
		Check{
			checkB64Parameters,
			5,
			"base64-parameters",
			"The link might contain base64 encoded parameters (low confidence)",
		},
	}
}
