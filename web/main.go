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
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	pongo "github.com/flosch/pongo2"
	"github.com/gobuffalo/packr"
	"github.com/gorilla/mux"
	"github.com/mattn/go-colorable"
	"github.com/phishdetect/phishdetect/lib"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	portNumber string
	apiVersion string

	templatesBox packr.Box
	staticBox    packr.Box

	tmplIndex    *pongo.Template
	tmplError    *pongo.Template
	tmplSubmit   *pongo.Template
	tmplCheck    *pongo.Template
	tmplRedirect *pongo.Template
	tmplWarning  *pongo.Template
)

const urlRegex string = "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"

func encodeSHA1(target string) string {
	h := sha1.New()
	h.Write([]byte(target))
	return hex.EncodeToString(h.Sum(nil))
}

func init() {
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.StringVar(&portNumber, "port", "7856", "Specify which port number to bind the service on")
	flag.StringVar(&apiVersion, "api-version", "1.37", "Specify which Docker API version to use (default: 1.37)")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())

	templatesBox = packr.NewBox("templates")
	staticBox = packr.NewBox("static")

	tmplIndex = pongo.Must(pongo.FromString(templatesBox.String("index.html")))
	tmplError = pongo.Must(pongo.FromString(templatesBox.String("error.html")))
	tmplSubmit = pongo.Must(pongo.FromString(templatesBox.String("submit.html")))
	tmplCheck = pongo.Must(pongo.FromString(templatesBox.String("check.html")))
	tmplRedirect = pongo.Must(pongo.FromString(templatesBox.String("redirect.html")))
	tmplWarning = pongo.Must(pongo.FromString(templatesBox.String("warning.html")))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug(r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func errorPage(w http.ResponseWriter, message string) {
	err := tmplError.ExecuteWriter(pongo.Context{
		"message": message,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, "Some unexpected error occurred! :-(", http.StatusInternalServerError)
	}
	return
}

func main() {
	fs := http.FileServer(staticBox)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(loggingMiddleware)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	router.HandleFunc("/", index)
	router.HandleFunc("/check/", check)
	router.HandleFunc(fmt.Sprintf("/check/{url:%s}", urlRegex), check).Methods("GET", "POST")
	router.HandleFunc("/analyze/", analyze).Methods("POST")

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http.ServeFile(w, r, "static/404.html")
		log.Warning(r.RequestURI)
	})

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

func index(w http.ResponseWriter, r *http.Request) {
	err := tmplIndex.ExecuteWriter(nil, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func check(w http.ResponseWriter, r *http.Request) {
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

func analyze(w http.ResponseWriter, r *http.Request) {
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
		// We do some validation checks for the URL to avoid potential file
		// disclosure issues.
		linkTest, err := phishdetect.NewLink(urlNormalized)
		if err != nil {
			log.Error(err)
			errorPage(w, "Something failed parsing the link. It might be invalid.")
			return
		}
		if linkTest.Scheme != "" && linkTest.Scheme != "http" && linkTest.Scheme != "https" {
			errorPage(w, "I only support HTTP links.")
			return
		}

		// Setting Docker API version.
		os.Setenv("DOCKER_API_VERSION", apiVersion)
		// Instantiate new browser and open the link.
		browser := phishdetect.NewBrowser(urlNormalized, "", tor)
		err = browser.Run()
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
