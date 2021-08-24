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

package phishdetect

import (
	"fmt"

	"github.com/phishdetect/phishdetect/brands"
	"github.com/phishdetect/phishdetect/browser"
	"github.com/phishdetect/phishdetect/checks"
	"github.com/phishdetect/phishdetect/link"
	"github.com/phishdetect/phishdetect/page"
	log "github.com/sirupsen/logrus"
)

// Warning is a converstion of Check containing only results.
type Warning struct {
	Score       int         `json:"score"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Matches     interface{} `json:"matches"`
}

// Analysis contains information on the outcome of the URL and/or HTML analysis.
type Analysis struct {
	URL        string         `json:"url"`
	FinalURL   string         `json:"final_url"`
	HTML       string         `json:"html"`
	Warnings   []Warning      `json:"warnings"`
	Score      int            `json:"score"`
	Safelisted bool           `json:"safelisted"`
	Dangerous  bool           `json:"dangerous"`
	Brands     *brands.Brands `json:"brands"`
}

// LoadYaraRules allows to pre-load Yara rules to be used during analysis.
// NOTE: This is mostly intended to avoid library users from having to import
//       the "check" package.
func LoadYaraRules(yaraRulesPath string) error {
	return checks.InitializeYara(yaraRulesPath)
}

// AddSafeBrowsingKey allows to pre-load a key for Google SafeBrowsing lookups.
// NOTE: This is mostly intended to avoid library users from having to import
//       the "check" package.
func AddSafeBrowsingKey(key string) {
	checks.SafeBrowsingKey = key
}

// NewAnalysis instantiates a new Analysis struct.
func NewAnalysis(url, html string) *Analysis {
	brandsList := brands.New()
	return &Analysis{
		URL:      url,
		FinalURL: url,
		HTML:     html,
		Brands:   brandsList,
	}
}

func (a *Analysis) analyzeDomainOrURL(checks []checks.Check) error {
	log.Debug("Starting to analyze the URL...")

	link, err := link.New(a.FinalURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL, might be invalid: %v", err)
	}
	for _, check := range checks {
		log.Debug("Running domain check ", check.Name, " ...")
		matched, matches := check.Call(link, nil, nil, a.Brands)
		if matched {
			log.Debug("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, Warning{
				Score:       check.Score,
				Name:        check.Name,
				Description: check.Description,
				Matches:     matches,
			})
		}
	}

	a.Safelisted = a.Brands.IsDomainSafelisted(link.TopDomain, "")
	// If the domain is marked as safelisted, we check if the link matches
	// any dangerous pattern.
	if a.Safelisted {
		a.Dangerous = a.Brands.IsLinkDangerous(link.URL, "")
	}

	return nil
}

// AnalyzeDomain performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeDomain() error {
	return a.analyzeDomainOrURL(checks.GetDomainChecks())
}

// AnalyzeURL performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeURL() error {
	return a.analyzeDomainOrURL(checks.GetURLChecks())
}

func (a *Analysis) analyzeHTML(browser *browser.Browser) error {
	log.Debug("Starting to analyze HTML...")

	link, err := link.New(a.FinalURL)
	if err != nil {
		return fmt.Errorf("failed parsing the link, it might be invalid: %v",
			err)
	}
	page, err := page.New(a.HTML)
	if err != nil {
		return err
	}

	for _, check := range checks.GetHTMLChecks() {
		log.Debug("Running HTML check ", check.Name, " ...")
		matched, matches := check.Call(link, page, browser, a.Brands)
		if matched {
			log.Debug("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, Warning{
				Score:       check.Score,
				Name:        check.Name,
				Description: check.Description,
				Matches:     matches,
			})
		}
	}

	return nil
}

// AnalyzeHTML performs all the available checks to be run on an HTML string.
func (a *Analysis) AnalyzeHTML() error {
	return a.analyzeHTML(nil)
}

// AnalyzeBrowserResults performs all the available checks to be run on an HTML string
// as well as the provided list of HTTP requests (e.g. downloaded scripts).
func (a *Analysis) AnalyzeBrowserResults(browser *browser.Browser) error {
	return a.analyzeHTML(browser)
}
