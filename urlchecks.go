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
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/google/safebrowsing"
	log "github.com/sirupsen/logrus"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

// SafeBrowsingKey contains the API key to use Google SafeBrowsing API.
var SafeBrowsingKey string

func checkSuspiciousHostname(link *Link, page *Page, brands *Brands) bool {
	lowSuspects := []string{
		"auth",
		"authorize",
		"authorization",
		"authenticate",
		"authentication",
		"account",
		"myaccount",
		"activate",
		"activation",
		"apps",
		"confirm",
		"confirmation",
		"credential",
		"drive",
		"login",
		"mails",
		"management",
		"password",
		"permission",
		"recover",
		"register",
		"safe",
		"secure",
		"security",
		"session",
		"signin",
		"support",
		"unlock",
		"update",
		"verify",
		"verification",
		"wallet",
		"weblogin",
	}

	normalized := strings.Replace(link.Domain, ".", "|", -1)
	normalized = strings.Replace(normalized, "-", "|", -1)
	words := strings.Split(normalized, "|")

	high := 0
	low := 0

	for _, word := range words {
		// First we check any potential words related to brands.
		for _, brand := range brands.List {
			// We check if a word in the domain is among any brand's
			// list of suspicious words.
			if SliceContains(brand.Suspicious, word) {
				// A suspicious brand name in the domain should have more
				// weight than anything.
				brand.Matches += 10
				return true
			}

			// If no obvious suspicious word is found, we do some additional
			// checks ...
			for _, original := range brand.Original {
				// First we check if there is a clean brand name in the domain.
				if strings.ToLower(word) == strings.ToLower(original) {
					// A brand name in a domain should have more weight
					// than a brand name in the page HTML.
					brand.Matches += 3
					high++
					break
				}

				// Then we check for any word within a certain edit distance.
				// This should normally be covered in the brand.Suspicious list,
				// but just in case we perform some additional test.
				if len(original) >= 5 && len(word) >= 5 {
					// We skip if the word is among those that with an edit
					// distance of 1 could cause too many false positives.
					// e.g. "icloud" => "cloud".
					exclude := []string{"cloud"}
					if SliceContains(exclude, word) {
						continue
					}

					distance := levenshtein.DistanceForStrings([]rune(word),
						[]rune(original), levenshtein.DefaultOptions)

					// We treat any distance higher than 1 as a false positive.
					if distance == 1 {
						brand.Matches += 5
						high++
						break
					}
				}
			}
		}

		// Then we check generic words.
		for _, suspect := range lowSuspects {
			// Check for any direct match.
			if strings.ToLower(word) == strings.ToLower(suspect) {
				low++
				break
			}

			// Check for any variation.
			if len(suspect) >= 5 && len(word) >= 5 {
				distance := levenshtein.DistanceForStrings([]rune(word),
					[]rune(suspect), levenshtein.DefaultOptions)

				// Anything above 2 edit distance, we consider a false positve.
				if distance == 1 || (distance == 2 && len(word) >= 7 && len(suspect) >= 7) {
					low++
					break
				}
			}
		}
	}

	if high >= 2 || (high >= 1 && low >= 1) || low >= 2 {
		return true
	}

	return false
}

func checkSuspiciousTLD(link *Link, page *Page, brands *Brands) bool {
	suspects := []string{
		".bank",
		".biz",
		".cc",
		".center",
		".cf",
		".click",
		".club",
		".co",
		".download",
		".ga",
		".gb",
		".gdn",
		".gg",
		".gq",
		".icu",
		".info",
		".live",
		".ml",
		".mobi",
		".online",
		".pro",
		".pw",
		".science",
		".services",
		".site",
		".stream",
		".support",
		".systems",
		".tech",
		".tk",
		".top",
		".vip",
		".win",
		".xin",
		".xyz",
	}

	for _, suspect := range suspects {
		if strings.HasSuffix(link.Domain, suspect) {
			return true
		}
	}

	return false
}

func checkSuspiciousBridges(link *Link, page *Page, brands *Brands) bool {
	suspects := []string{".com-", ".org-"}

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
		if len(value) <= 8 {
			continue
		}
		_, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return true
		}
	}

	return false
}

func checkGoogleSafeBrowsing(link *Link, page *Page, brands *Brands) bool {
	if SafeBrowsingKey == "" {
		return false
	}

	log.Debug("Using Google SafeBrowsing API key: ", SafeBrowsingKey)

	sb, err := safebrowsing.NewSafeBrowser(safebrowsing.Config{
		APIKey: SafeBrowsingKey,
	})
	if err != nil {
		log.Error(err.Error())
		return false
	}

	threats, err := sb.LookupURLs([]string{link.URL})
	if err != nil {
		log.Error(err.Error())
		return false
	}

	if len(threats[0]) > 0 {
		for _, threat := range threats {
			log.Debug(threat)
		}
		return true
	}

	log.Debug("No Google SafeBrowsing threats found for this URL")

	return false
}

// GetDomainChecks returns a list of only the checks that work for domain names.
func GetDomainChecks() []Check {
	return []Check{
		{
			checkSuspiciousTLD,
			5,
			"suspicious-tld",
			"The domain uses a suspicious TLD",
		},
		{
			checkExcessivePunct,
			20,
			"excessive-punct",
			"The domain has suspicious amount of dots and dashes",
		},
		{
			checkSuspiciousBridges,
			25,
			"suspicious-bridges",
			"The domain uses very suspicious patterns used for bad domains composition",
		},
		{
			checkSuspiciousHostname,
			30,
			"suspicious-hostname",
			"The domain contains suspicious words",
		},
		{
			checkEncodedDomain,
			50,
			"encoded-domain",
			"The domain contains special characters to mimic known brands",
		},
		{
			checkGoogleSafeBrowsing,
			50,
			"google-safebrowsing",
			"The link is listed in Google SafeBrowsing as malicious",
		},
	}
}

// GetURLChecks returns a list of all the available URL checks.
func GetURLChecks() []Check {
	checks := GetDomainChecks()
	checks = append(checks, []Check{
		{
			checkB64Parameters,
			5,
			"base64-parameters",
			"The link might contain base64 encoded parameters (low confidence)",
		},
		{
			checkNoTLS,
			15,
			"no-tls",
			"The website is not using a secure transport layer (HTTPS)",
		},
	}...)

	return checks
}
