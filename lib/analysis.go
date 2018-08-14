package phishdetect

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

// Analysis contains information on the outcome of the URL and/or HTML analysis.
type Analysis struct {
	URL         string
	FinalURL    string
	HTML        string
	Warnings    []Check
	Score       int
	Whitelisted bool
	Brands      *Brands
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

// AnalyzeURL performs all the available checks to be run on a URL or domain.
func (a *Analysis) AnalyzeURL() error {
	log.Info("Starting to analyze the URL...")

	link, err := NewLink(a.FinalURL)
	if err != nil {
		return errors.New("An error occurred parsing the link, it might be invalid.")
	}
	for _, check := range GetURLChecks() {
		log.Debug("Running URL check ", check.Name, " ...")
		if check.Call(link, nil, a.Brands) {
			log.Info("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, check)
		}
	}

	a.Whitelisted = a.Brands.IsDomainWhitelisted(link.TopDomain, "")

	return nil
}

// AnalyzeHTML performs all the available checks to be run on an HTML string.
func (a *Analysis) AnalyzeHTML() error {
	log.Info("Starting to analyze HTML...")

	link, err := NewLink(a.FinalURL)
	if err != nil {
		return errors.New("An error occurred parsing the link. It might be invalid.")
	}
	page, err := NewPage(a.HTML)
	if err != nil {
		return err
	}

	for _, check := range GetHTMLChecks() {
		log.Debug("Running HTML check ", check.Name, " ...")
		if check.Call(link, page, a.Brands) {
			log.Info("Matched ", check.Name)
			a.Score += check.Score
			a.Warnings = append(a.Warnings, check)
		}
	}

	return nil
}
