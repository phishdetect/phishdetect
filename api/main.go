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
	"os"
	"io/ioutil"
	"fmt"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattn/go-colorable"
	"github.com/phishdetect/phishdetect"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

// AnalysisResults contains all the information we want to return through the
// apiAnalyze API.
type AnalysisResults struct {
	URL         string   `json:"url"`
	URLFinal    string   `json:"url_final"`
	Whitelisted bool     `json:"whitelisted"`
	Brand       string   `json:"brand"`
	Score       int      `json:"score"`
	Warnings    []string `json:"warnings"`
}

var (
	portNumber   string
	apiVersion   string
	safeBrowsing string
)

func init() {
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.StringVar(&portNumber, "port", "6745", "Specify which port number to bind the service on")
	flag.StringVar(&apiVersion, "api-version", "1.37", "Specify which Docker API version to use (default: 1.37)")
	flag.StringVar(&safeBrowsing, "safebrowsing", "", "Specify a file path containing your Google SafeBrowsing API key (default: disabled)")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())

	if safeBrowsing != "" {
		if _, err := os.Stat(safeBrowsing); err == nil {
			buf, _ := ioutil.ReadFile(safeBrowsing)
			key := string(buf)
			if key != "" {
				phishdetect.SafeBrowsingKey = key
			}
		} else {
			log.Warning("The specified Google SafeBrowsing API key file does not exist. Check disabled.")
		}
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug(r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func main() {
	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(loggingMiddleware)
	router.HandleFunc("/api/analyze/", apiAnalyze).Methods("POST")

	hostPort := fmt.Sprintf("127.0.0.1:%s", portNumber)
	srv := &http.Server{
		Handler:      router,
		Addr:         hostPort,
		WriteTimeout: 2 * time.Minute,
		ReadTimeout:  2 * time.Minute,
	}

	log.Info("Starting server on ", hostPort, " and waiting for requests...")

	log.Fatal(srv.ListenAndServe())
}

func apiAnalyze(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	url := r.PostFormValue("url")
	urlFinal := url
	// urlNormalized := phishdetect.NormalizeURL(url)
	// full, _ := strconv.ParseBool(r.PostFormValue("full"))

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	err := analysis.AnalyzeURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL: url,
		// URLFinal: urlFinal,
		Whitelisted: analysis.Whitelisted,
		Score:       analysis.Score,
		Brand:       brand,
		Warnings:    warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
