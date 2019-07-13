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

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-colorable"
	"github.com/phishdetect/phishdetect"
	"github.com/phishdetect/phishdetect/brand"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

var (
	analysis *phishdetect.Analysis
	browser  *phishdetect.Browser
	customBrands []*brand.Brand
)

func initLogging(debug *bool) {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())
}


func compileBrands(brandsPath string) []*brand.Brand {
	if brandsPath == "" {
		return nil
	}

	if _, err := os.Stat(brandsPath); os.IsNotExist(err) {
		log.Warning("The specified brands folder does not exist, skipping")
		return nil
	}

	filePaths := []string{}
	filepath.Walk(brandsPath, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(strings.ToLower(path))
		if ext == ".yaml" || ext == ".yml" {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	brands := []*brand.Brand{}

	for _, path := range filePaths {
		log.Debug("Trying to load custom brand file at path ", path)
		customBrand := brand.Brand{}
		yamlFile, err := ioutil.ReadFile(path)
		err = yaml.Unmarshal(yamlFile, &customBrand)
		if err != nil {
			log.Warning("Failed to load brand file: ", err.Error())
			continue
		}

		log.Debug("Loaded custom brand with name: ", customBrand.Name)

		brands = append(brands, &customBrand)
	}

	return brands
}

func loadBrands(analysis phishdetect.Analysis) {
	for _, customBrand := range customBrands {
		analysis.Brands.AddBrand(customBrand)
	}

	return
}

func main() {
	debug := flag.Bool("debug", false, "Enable debug logging")
	tor := flag.Bool("tor", false, "Route connection through the Tor network")
	apiVersion := flag.String("api-version", "1.37", "Specify which Docker API version to use")
	urlOnly := flag.Bool("url-only", false, "Only perform URL analysis")
	screenPath := flag.String("screen", "", "Specify the file path to store the screenshot")
	safeBrowsing := flag.String("safebrowsing", "", "Specify a file path containing your Google SafeBrowsing API key")
	container := flag.String("container", "phishdetect/phishdetect", "Specify a name for a docker image to use")
	brandsPath := flag.String("brands", "", "Specify a folder containing YAML files with Brand specifications")
	flag.Parse()
	args := flag.Args()

	initLogging(debug)

	log.Debug("Flags: enable debug logs: ", *debug)
	log.Debug("Flags: enable Tor routing: ", *tor)
	log.Debug("Flags: Docker API Version: ", *apiVersion)
	log.Debug("Flags: only URL analysis: ", *urlOnly)
	log.Debug("Flags: screenshot path: ", *screenPath)
	log.Debug("Flags: Google SafeBrowsing API key file: ", *safeBrowsing)
	log.Debug("Flags: Brands path: ", *brandsPath)
	log.Debug("Flags: arguments: ", args)

	if len(args) == 0 {
		log.Fatal("You need to provide a valid URL to be analyzed!")
	}

	customBrands = compileBrands(*brandsPath)

	if *safeBrowsing != "" {
		if _, err := os.Stat(*safeBrowsing); err == nil {
			buf, _ := ioutil.ReadFile(*safeBrowsing)
			key := string(buf)
			if key != "" {
				phishdetect.SafeBrowsingKey = key
			}
		} else {
			log.Warning("The specified Google SafeBrowsing API key file does not exist. Check disabled.")
		}
	}

	os.Setenv("DOCKER_API_VERSION", *apiVersion)

	url := args[0]

	log.Info("Analyzing URL ", url)

	if *urlOnly {
		log.Debug("Instantiated url-only analysis.")
		analysis = phishdetect.NewAnalysis(url, "")
		loadBrands(*analysis)
	} else {
		browser = phishdetect.NewBrowser(phishdetect.NormalizeURL(url), *screenPath, *tor, *container)
		err := browser.Run()
		if err != nil {
			log.Fatal(err)
		}

		analysis = phishdetect.NewAnalysis(url, browser.HTML)
		loadBrands(*analysis)
		analysis.AnalyzeHTML()

		if strings.HasPrefix(browser.FinalURL, "chrome-error://") {
			log.Fatal("An error occurred visiting the link. The website might be offline.")
		}

		if browser.FinalURL != "" {
			analysis.FinalURL = browser.FinalURL
			log.Debug("Going to use final URL for analysis ", analysis.FinalURL)
		}
	}

	analysis.AnalyzeURL()
	brand := analysis.Brands.GetBrand()

	if !*urlOnly {
		log.Info("Visits:")
		for _, visit := range browser.Visits {
			log.Info("\t- ", visit)
		}
		log.Info("Final URL: ", browser.FinalURL)
	}
	log.Info("Whitelisted: ", analysis.Whitelisted)
	log.Info("Final score: ", analysis.Score)

	log.Debug("All brands scores:")
	for _, brand := range analysis.Brands.List {
		if brand.Matches == 0 {
			continue
		}

		log.Debug("\t- ", brand.Name, ": ", brand.Matches)
	}

	log.Info("Brand: ", brand)
	log.Info("Warnings:")
	for _, warning := range analysis.Warnings {
		log.WithFields(log.Fields{"name": warning.Name, "score": warning.Score}).
			Info("\t- ", warning.Description)
	}
}
