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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	pongo "github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	"github.com/phishdetect/phishdetect"
	log "github.com/sirupsen/logrus"
)

func interfaceIndex(w http.ResponseWriter, r *http.Request) {
	err := tmplIndex.ExecuteWriter(nil, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func interfaceCheck(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	urlEncoded := vars["url"]

	// If no url was specified, we show the submit form.
	if urlEncoded == "" {
		err := tmplSubmit.ExecuteWriter(nil, w)
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// If a url was specified, we determine how to analyze it.
	} else {
		data, err := base64.StdEncoding.DecodeString(urlEncoded)
		if err != nil {
			log.Error(err)
			errorPage(w, "You submitted an invalid URL argument. I expect a base64 encoded URL.")
			return
		}

		// The url is normally send base64-encoded.
		urlDecoded := string(data)
		log.Info("Received analysis request for ", urlDecoded)

		// Check for "tor" query value.
		tor := ""
		torS, ok := r.URL.Query()["tor"]
		if ok {
			tor = torS[0]
		}
		// Check for "force" query value.
		force := ""
		forceS, ok := r.URL.Query()["force"]
		if ok {
			force = forceS[0]
		}

		// These options are used if the user sent an HTML page from the
		// browser extension.
		html := ""
		screenshot := ""
		if r.Method == "POST" {
			r.ParseForm()
			// We get the base64 encoded HTML page.
			html = r.PostFormValue("html")
			// We are gonna display the screenshot sent by the browser.
			screenshot = r.PostFormValue("screenshot")
		}

		err = tmplCheck.ExecuteWriter(pongo.Context{
			"url":        urlDecoded,
			"html":       html,
			"screenshot": screenshot,
			"tor":        tor,
			"force":      force,
		}, w)
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func interfaceAnalyze(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	url := r.PostFormValue("url")
	urlSHA1 := encodeSHA1(url)
	htmlEncoded := r.PostFormValue("html")
	screenshot := r.PostFormValue("screenshot")
	tor, _ := strconv.ParseBool(r.PostFormValue("tor"))
	// force 	:= r.PostFormValue("force")

	html := ""

	// For the moment, urlFinal will be the original URL.
	urlFinal := url
	urlNormalized := phishdetect.NormalizeURL(url)

	// If there is no specified HTML string, it means we need to open the link.
	if htmlEncoded == "" {
		if !validateURL(url) {
			errorPage(w, "You have submitted an invalid link.")
		}

		// Setting Docker API version.
		os.Setenv("DOCKER_API_VERSION", apiVersion)
		// Instantiate new browser and open the link.
		browser := phishdetect.NewBrowser(urlNormalized, "", tor, "")
		err := browser.Run()
		if err != nil {
			log.Error(err)
			errorPage(w, "Something failed while trying to launch the containerized browser. The URL might be invalid.")
			return
		}
		html = browser.HTML
		urlFinal = browser.FinalURL
		screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)
		// Otherwise, we decode the base64-encoded HTML string and use that.
	} else {
		data, err := base64.StdEncoding.DecodeString(htmlEncoded)
		if err != nil {
			log.Error(err)
			errorPage(w, "I received invalid HTML data. I expect a base64 encoded string.")
			return
		}
		html = string(data)
	}

	// Check for Chrome errors, generally raised by connection failures.
	if strings.HasPrefix(urlFinal, "chrome-error://") {
		errorPage(w, "An error occurred while visiting the link. The website might be offline.")
		return
	}

	// Now that we have URL and HTML we can analyze results.
	analysis := phishdetect.NewAnalysis(urlFinal, html)
	err := analysis.AnalyzeHTML()
	if err != nil {
		errorPage(w, err.Error())
		return
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		errorPage(w, err.Error())
		return
	}
	brand := analysis.Brands.GetBrand()

	log.Info("Completed analysis of ", url)

	// If the site is whitelisted, or the final score is low, we offer the
	// redirect to the original link.
	if analysis.Whitelisted || analysis.Score < 30 {
		err := tmplRedirect.ExecuteWriter(pongo.Context{
			"url":           url,
			"urlNormalized": urlNormalized,
			"urlFinal":      urlFinal,
			"sha1":          urlSHA1,
			"brand":         brand,
			"whitelisted":   analysis.Whitelisted,
			"screenshot":    screenshot,
		}, w)
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// At this point we return or the function will continue.
		return
	}

	// Otherwise we show the warning.
	err = tmplWarning.ExecuteWriter(pongo.Context{
		"url":           url,
		"urlNormalized": urlNormalized,
		"urlFinal":      urlFinal,
		"sha1":          urlSHA1,
		"warnings":      analysis.Warnings,
		"brand":         brand,
		"score":         analysis.Score,
		"screenshot":    screenshot,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
