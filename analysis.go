// PhishDetect
// Copyright (c) 2018-2020 Claudio Guarnieri.
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
	"errors"

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
	URL        string    `json:"url"`
	FinalURL   string    `json:"final_url"`
	HTML       string    `json:"html"`
	Warnings   []Warning `json:"warnings"`
	Score      int       `json:"score"`
	Safelisted bool      `json:"safelisted"`
	Dangerous  bool      `json:"dangerous"`
	Brands     *Brands   `json:"brands"`
}

// NewAnalysis instantiates a new Analysis struct.
func NewAnalysis(url, html string) *Analysis {
	brands := NewBrands()
	return &Analysis{
		URL:      url,
		FinalURL: url,
		HTML:     html,
		Brands:   brands,
	}
}

func (a *Analysis) analyzeDomainOrURL(checks []Check) error {
	log.Debug("Starting to analyze the URL...")

	link, err := NewLink(a.FinalURL)
	if err != nil {
		return errors.New("An error occurred parsing the domain, it might be invalid")
	}
	for _, check := range checks {
		log.Debug("Running domain check ", check.Name, " ...")
		matched, matches := check.Call(link, nil, ResourcesData{}, a.Brands)
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
	return a.analyzeDomainOrURL(GetDomainChecks())
}

// AnalyzeURL performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeURL() error {
	return a.analyzeDomainOrURL(GetURLChecks())
}

func (a *Analysis) analyzeHTML(resourcesData ResourcesData) error {
	log.Debug("Starting to analyze HTML...")

	link, err := NewLink(a.FinalURL)
	if err != nil {
		return errors.New("An error occurred parsing the link: it might be invalid")
	}
	page, err := NewPage(a.HTML)
	if err != nil {
		return err
	}

	for _, check := range GetHTMLChecks() {
		log.Debug("Running HTML check ", check.Name, " ...")
		matched, matches := check.Call(link, page, resourcesData, a.Brands)
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
	return a.analyzeHTML(ResourcesData{})
}

// AnalyzeBrowserResults performs all the available checks to be run on an HTML string
// as well as the provided list of HTTP requests (e.g. downloaded scripts).
func (a *Analysis) AnalyzeBrowserResults(resourcesData ResourcesData) error {
	return a.analyzeHTML(resourcesData)
}
