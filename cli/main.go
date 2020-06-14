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
	analysis     *phishdetect.Analysis
	browser      *phishdetect.Browser
	customBrands []*brand.Brand

	debug        bool
	tor          bool
	apiVersion   string
	urlOnly      bool
	screenPath   string
	safeBrowsing string
	container    string
	brandsPath   string
	yaraPath     string
	htmlPath     string
	args         []string
)

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

func initLogging() {
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())
}

func init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&tor, "tor", false, "Route connection through the Tor network")
	flag.StringVar(&apiVersion, "api-version", "1.37", "Specify which Docker API version to use")
	flag.BoolVar(&urlOnly, "url-only", false, "Only perform URL analysis")
	flag.StringVar(&screenPath, "screen", "", "Specify the file path to store the screenshot")
	flag.StringVar(&safeBrowsing, "safebrowsing", "", "Specify a file path containing your Google SafeBrowsing API key")
	flag.StringVar(&container, "container", "phishdetect/phishdetect", "Specify a name for a docker image to use")
	flag.StringVar(&brandsPath, "brands", "", "Specify a folder containing YAML files with Brand specifications")
	flag.StringVar(&yaraPath, "yara", "", "Specify a path to a file or folder contaning Yara rules")
	flag.StringVar(&htmlPath, "html", "", "Specify a path to save the HTML from the visited page")
	flag.Parse()
	args = flag.Args()

	initLogging()

	log.Debug("Flags: enable debug logs: ", debug)
	log.Debug("Flags: enable Tor routing: ", tor)
	log.Debug("Flags: Docker API Version: ", apiVersion)
	log.Debug("Flags: only URL analysis: ", urlOnly)
	log.Debug("Flags: screenshot path: ", screenPath)
	log.Debug("Flags: Google SafeBrowsing API key file: ", safeBrowsing)
	log.Debug("Flags: Brands path: ", brandsPath)
	log.Debug("Flags: Yara rules path: ", yaraPath)
	log.Debug("Flags: arguments: ", args)

	if len(args) == 0 {
		log.Fatal("You need to provide a valid URL to be analyzed!")
	}
}

func main() {
	customBrands = compileBrands(brandsPath)

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

	if yaraPath != "" {
		if _, err := os.Stat(yaraPath); err == nil {
			err = phishdetect.InitializeYara(yaraPath)
			if err != nil {
				log.Warning("Failed to initialize Yara scanner: ", err.Error())
			}
		} else {
			log.Warning("The specified path to the Yara rules does not exist")
		}
	}

	os.Setenv("DOCKER_API_VERSION", apiVersion)

	url := args[0]

	log.Info("Analyzing URL ", url)

	if urlOnly {
		log.Debug("Instantiated url-only analysis.")
		analysis = phishdetect.NewAnalysis(url, "")
		loadBrands(*analysis)
	} else {
		browser = phishdetect.NewBrowser(phishdetect.NormalizeURL(url), screenPath, tor, container)
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

		if htmlPath != "" {
			err = ioutil.WriteFile(htmlPath, []byte(browser.HTML), 0644)
			if err != nil {
				log.Error(err.Error())
			} else {
				log.Info("Saved HTML page at ", htmlPath)
			}
		}

		if browser.FinalURL != "" {
			analysis.FinalURL = browser.FinalURL
			log.Debug("Going to use final URL for analysis ", analysis.FinalURL)
		}
	}

	analysis.AnalyzeURL()
	brand := analysis.Brands.GetBrand()

	if !urlOnly {
		log.Info("Visits:")
		for _, visit := range browser.Visits {
			log.Info("\t- ", visit)
		}
		log.Info("Final URL: ", browser.FinalURL)
	}

	for _, resource := range browser.Resources {
		log.Info("Resource of type ", resource.Type, " at URL ", resource.URL)
		if resource.SHA256 != "" {
			log.Info("\twith hash ", resource.SHA256)
		}
	}

	log.Info("Safelisted: ", analysis.Safelisted)
	log.Info("Final score: ", analysis.Score)

	log.Info("Brand: ", brand)
	log.Debug("All brands scores:")
	for _, brand := range analysis.Brands.List {
		if brand.Matches == 0 {
			continue
		}

		log.Debug("\t- ", brand.Name, ": ", brand.Matches)
	}

	log.Info("Warnings:")
	for _, warning := range analysis.Warnings {
		log.WithFields(log.Fields{"name": warning.Name, "score": warning.Score}).
			Info("\t- ", warning.Description)
	}
}
