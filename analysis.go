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
	"errors"

	log "github.com/sirupsen/logrus"
)

// Analysis contains information on the outcome of the URL and/or HTML analysis.
type Analysis struct {
	URL        string
	FinalURL   string
	HTML       string
	Warnings   []Check
	Score      int
	Safelisted bool
	Brands     *Brands
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

func (a *Analysis) analyzeLink(checks []Check) error {
	log.Debug("Starting to analyze the URL...")

	link, err := NewLink(a.FinalURL)
	if err != nil {
		return errors.New("An error occurred parsing the domain, it might be invalid")
	}
	for _, check := range checks {
		log.Debug("Running domain check ", check.Name, " ...")
		if check.Call(link, nil, a.Brands) {
			log.Debug("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, check)
		}
	}

	a.Safelisted = a.Brands.IsDomainSafelisted(link.TopDomain, "")

	return nil
}

// AnalyzeDomain performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeDomain() error {
	return a.analyzeLink(GetDomainChecks())
}

// AnalyzeURL performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeURL() error {
	return a.analyzeLink(GetURLChecks())
}

// AnalyzeHTML performs all the available checks to be run on an HTML string.
func (a *Analysis) AnalyzeHTML() error {
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
		if check.Call(link, page, a.Brands) {
			log.Debug("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, check)
		}
	}

	return nil
}
