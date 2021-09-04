// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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

package checks

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/botherder/go-savetime/slice"
	"github.com/google/safebrowsing"
	"github.com/phishdetect/phishdetect/brands"
	"github.com/phishdetect/phishdetect/browser"
	"github.com/phishdetect/phishdetect/link"
	"github.com/phishdetect/phishdetect/page"
	log "github.com/sirupsen/logrus"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

// SafeBrowsingKey contains the API key to use Google SafeBrowsing API.
var SafeBrowsingKey string

func checkSuspiciousHostname(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	lowSuspects := []string{
		"auth",
		"authorise",
		"authorize",
		"authorisation",
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
		"https",
		"login",
		"mails",
		"management",
		"notice",
		"password",
		"payee",
		"payees",
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
		excludeWord := false

		// First we check any potential words related to brands.
		for _, brand := range brands.List {
			// If the word is contained within the exclusions list,
			// we skip it.
			if slice.ContainsNoCase(brand.Exclusions, word) {
				excludeWord = true
				break
			}

			// We check if a word in the domain is among any brand's
			// list of suspicious words.
			for _, suspicious := range brand.Suspicious {
				// Check for direct match.
				if strings.ToLower(word) == strings.ToLower(suspicious) {
					brand.Matches += 10
					return true, nil
				}
			}

			// If no obvious suspicious word is found, we do some additional
			// checks ...
			for _, original := range brand.Original {
				// If the original brand name is contained as a substring to
				// the word we consider it a high-risk indicator.
				if strings.Contains(strings.ToLower(word), strings.ToLower(original)) {
					brand.Matches += 3
					high++
					break
				}

				// Then we check for any word within a certain edit distance.
				// This should normally be covered in the brand.Suspicious list,
				// but just in case we perform some additional test.
				if len(original) >= 5 && len(word) >= 5 {
					distance := levenshtein.DistanceForStrings([]rune(word),
						[]rune(original), levenshtein.DefaultOptions)

					// We treat any distance higher than 1 as a false positive.
					// In cases of words with length >= 10 we also accept a
					// distance of 2 as suspicious.
					if distance == 1 || (len(word) >= 10 && distance == 2) {
						brand.Matches += 5
						high++
						break
					}
				}
			}
		}

		// If the current word was found to be excluded, we do not continue
		// any further.
		if excludeWord == true {
			continue
		}

		// Then we check generic words.
		for _, suspect := range lowSuspects {
			// Check if one of the suspect words is contained in the currently
			// checked word.
			if strings.Contains(strings.ToLower(word), strings.ToLower(suspect)) {
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
		return true, nil
	}

	return false, nil
}

func checkSuspiciousTLD(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
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
		".finance",
		".ga",
		".gb",
		".gdn",
		".gg",
		".gq",
		".icu",
		".info",
		".link",
		".live",
		".me",
		".ml",
		".mobi",
		".online",
		".pro",
		".pw",
		".science",
		".services",
		".site",
		".space",
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
			return true, nil
		}
	}

	return false, nil
}

func checkSuspiciousBridges(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	// ".www." causes too many false positives.
	suspects := []string{".com-", ".org-"}

	for _, suspect := range suspects {
		if strings.Contains(link.Domain, suspect) {
			return true, nil
		}
	}

	return false, nil
}

func checkEncodedDomain(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	if !strings.Contains(link.Domain, "xn--") {
		return false, nil
	}

	for _, brand := range brands.List {
		for _, word := range brand.Suspicious {
			if !strings.Contains(word, "xn--") {
				continue
			}

			if strings.Contains(link.Domain, word) {
				brand.Matches++
				return true, nil
			}
		}
	}

	return false, nil
}

func checkExcessivePunct(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
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
		return true, nil
	}

	return false, nil
}

func checkNoTLS(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	if strings.HasPrefix(link.Scheme, "http") {
		if link.Scheme != "https" {
			return true, nil
		}
	}

	return false, nil
}

func checkB64Parameters(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	for _, value := range link.Parameters {
		// We skip strings that are too short, because they could significantly
		// raise false positives.
		if len(value) <= 8 {
			continue
		}
		_, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return true, nil
		}
	}

	return false, nil
}

func checkGoogleSafeBrowsing(link *link.Link, page *page.Page, browser *browser.Browser, brands *brands.Brands) (bool, interface{}) {
	if SafeBrowsingKey == "" {
		return false, nil
	}

	log.Debug("Using Google SafeBrowsing API key: ", SafeBrowsingKey)

	sb, err := safebrowsing.NewSafeBrowser(safebrowsing.Config{
		APIKey: SafeBrowsingKey,
	})
	if err != nil {
		log.Error(err.Error())
		return false, nil
	}

	threats, err := sb.LookupURLs([]string{link.URL})
	if err != nil {
		log.Error(err.Error())
		return false, nil
	}

	if len(threats[0]) > 0 {
		for _, threat := range threats {
			log.Debug(threat)
		}
		return true, nil
	}

	log.Debug("No Google SafeBrowsing threats found for this URL")

	return false, nil
}

// GetDomainChecks returns a list of only the checks that work for domain names.
func GetDomainChecks() []Check {
	return []Check{
		{
			Call:        checkSuspiciousTLD,
			Score:       5,
			Name:        "suspicious-tld",
			Description: "The domain uses a suspicious TLD",
		},
		{
			Call:        checkExcessivePunct,
			Score:       20,
			Name:        "excessive-punct",
			Description: "The domain has suspicious amount of dots and dashes",
		},
		{
			Call:        checkSuspiciousBridges,
			Score:       25,
			Name:        "suspicious-bridges",
			Description: "The domain uses very suspicious patterns used for bad domains composition",
		},
		{
			Call:        checkSuspiciousHostname,
			Score:       30,
			Name:        "suspicious-hostname",
			Description: "The domain contains suspicious words",
		},
		{
			Call:        checkEncodedDomain,
			Score:       50,
			Name:        "encoded-domain",
			Description: "The domain contains special characters to mimic known brands",
		},
		{
			Call:        checkGoogleSafeBrowsing,
			Score:       50,
			Name:        "google-safebrowsing",
			Description: "The link is listed in Google SafeBrowsing as malicious",
		},
	}
}

// GetURLChecks returns a list of all the available URL checks.
func GetURLChecks() []Check {
	checks := GetDomainChecks()
	checks = append(checks, []Check{
		{
			Call:        checkB64Parameters,
			Score:       5,
			Name:        "base64-parameters",
			Description: "The link might contain base64 encoded parameters (low confidence)",
		},
		{
			Call:        checkNoTLS,
			Score:       15,
			Name:        "no-tls",
			Description: "The website is not using a secure transport layer (HTTPS)",
		},
	}...)

	return checks
}
