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

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/phishdetect/phishdetect"
	log "github.com/sirupsen/logrus"
)

// AnalysisRequest contains the information required to start an analysis.
type AnalysisRequest struct {
	URL  string `json:"url"`
	HTML string `json:"html"`
}

// AnalysisResults contains all the information we want to return through the
// apiAnalyze API.
type AnalysisResults struct {
	URL         string   `json:"url"`
	URLFinal    string   `json:"url_final"`
	Whitelisted bool     `json:"whitelisted"`
	Brand       string   `json:"brand"`
	Score       int      `json:"score"`
	Screenshot  string   `json:"screenshot"`
	Warnings    []string `json:"warnings"`
}

func apiAnalyzeDomain(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		// Couldn't parse request.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	log.Debug("Received request to statically analyze domain: ", req.URL)

	urlNormalized := phishdetect.NormalizeURL(req.URL)
	urlFinal := urlNormalized

	if !validateURL(urlNormalized) {
		// Invalid URL.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	err = analysis.AnalyzeDomain()
	if err != nil {
		// Analysis failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:         req.URL,
		URLFinal:    urlFinal,
		Whitelisted: analysis.Whitelisted,
		Score:       analysis.Score,
		Brand:       brand,
		Screenshot:  "",
		Warnings:    warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func apiAnalyzeLink(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		// Couldn't parse request.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	log.Debug("Received request to dynamically analyze link: ", req.URL)

	urlNormalized := phishdetect.NormalizeURL(req.URL)
	urlFinal := urlNormalized

	var html string
	var screenshot string

	if !validateURL(urlNormalized) {
		// Invalid URL.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Setting Docker API version.
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	// Instantiate new browser and open the link.
	browser := phishdetect.NewBrowser(urlNormalized, "", false, "")
	err = browser.Run()
	if err != nil {
		// Browser launch failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	html = browser.HTML
	urlFinal = browser.FinalURL
	screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	err = analysis.AnalyzeHTML()
	if err != nil {
		// Analysis failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		// Analysis failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:         req.URL,
		URLFinal:    urlFinal,
		Whitelisted: analysis.Whitelisted,
		Score:       analysis.Score,
		Brand:       brand,
		Screenshot:  screenshot,
		Warnings:    warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func apiAnalyzeHTML(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		// Couldn't parse request.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	log.Debug("Received request to statically analyze HTML from URL: ", req.URL)

	url := req.URL
	urlFinal := url

	if !validateURL(url) {
		// Invalid URL.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if req.HTML == "" {
		// Invalid HTML.
		http.Error(w, "Invalid HTML", http.StatusInternalServerError)
	}

	htmlData, err := base64.StdEncoding.DecodeString(req.HTML)
	if err != nil {
		// Invalid HTML.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	html := string(htmlData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	err = analysis.AnalyzeHTML()
	if err != nil {
		// Analysis failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		// Analysis failed.
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:         url,
		URLFinal:    urlFinal,
		Whitelisted: analysis.Whitelisted,
		Score:       analysis.Score,
		Brand:       brand,
		Screenshot:  "",
		Warnings:    warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
