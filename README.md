[![Build Status](https://api.travis-ci.org/phishdetect/phishdetect.png?branch=master)](https://travis-ci.org/phishdetect/phishdetect)
[![Go Report Card](https://goreportcard.com/badge/github.com/phishdetect/phishdetect)](https://goreportcard.com/report/github.com/phishdetect/phishdetect)
[![Go Reference](https://pkg.go.dev/badge/github.com/phishdetect/phishdetect.svg)](https://pkg.go.dev/github.com/phishdetect/phishdetect)

# PhishDetect

**NOTE: This project is experimental. It is not to be used yet, particularly with at-risk users.**

PhishDetect is a library and a platform to detect potential phishing pages. It attempts doing so by identifying suspicious and malicious properties both in the domain names and URL provided, as well as in the HTML content of the page opened.

PhishDetect can take HTML strings as input, but it can also just be provided with an URL which will then be opened through a dedicated Docker container which automatically instruments a Google Chrome browser, whose behavior is monitored while navigating to the suspicious link.


## Table of Contents

   * [PhishDetect](#phishdetect)
      * [Building](#building)
      * [Using PhishDetect as a library](#using-phishdetect-as-a-library)
         * [Analyzing a link statically](#analyzing-a-link-statically)
         * [Analyzing a link dynamically](#analyzing-a-link-dynamically)
         * [Adding new Brands to the existing list](#adding-new-brands-to-the-existing-list)
         * [Adding Yara rules to the HTML classifier](#adding-yara-rules-to-the-html-classifier)
      * [Using PhishDetect CLI](#using-phishdetect-cli)
      * [Known Issues](#known-issues)
      * [License](#license)


## Building

Install Docker Community Edition. Particularly when using this with [PhishDetect Node](https://github.com/phishdetect/phishdetect-node), you should be looking into installing Docker in [Rootless Mode](https://docs.docker.com/engine/security/rootless/). You can find more information about this in the Node's documentation.

Download the Docker image from Docker Hub using:

    $ docker pull phishdetect/phishdetect

You will also need to install Yara and its library. In order to do so, please follow the instructions provided by the official [Yara Project documentation](https://yara.readthedocs.org/en/latest/gettingstarted.html#compiling-and-installing-yara).

Now you can download the PhishDetect library:

    $ go get -u github.com/phishdetect/phishdetect

For ease of versioning, you should consider using Go 1.11+ Modules in your own project.


## Using PhishDetect as a library


### Analyzing a link statically

You can then use it to analyze a URL or a domain like so:

```go
package main

import (
    "fmt"
    "github.com/phishdetect/phishdetect"
)

func main() {
    // Instantiate an Analysis. The second argument is
    // an HTML string.
    a := phishdetect.NewAnalysis("example.com", "")
    // Perform the analysis of the URL/domain.
    a.AnalyzeURL()
    // Retrieve the name of the impersonated brand.
    brand := a.Brands.GetBrand()

    // If the domain is recognized as safelisted, this
    // will show as true, otherwise as false.
    fmt.Println(a.Safelisted)
    // This is a total numeric value that is the sum of
    // all the score values of the warnings that were
    // matched during the analysis.
    fmt.Println(a.Score)
    // Print the brand. It will be an empty string if
    // no brand was identified.
    fmt.Println(brand)

    // Print all the matched warnings from the analysis.
    for _, warning := range a.Warnings {
        fmt.Println(warning.Description)
    }
}
```

In addition, if you already have the HTML of a given page you want to analyze, you can supply it as a second argument to `NewAnalysis()` with `a := phishdetect.NewAnalysis(url, html)` and then invoke `a.AnalyzeHTML()`.


### Analyzing a link dynamically

If you want to analyze a URL by launching the dockerized Google Chrome:

```go
package main

import (
    "fmt"
    "github.com/phishdetect/phishdetect"
    "github.com/phishdetect/phishdetect/browser"
)

func main() {
    url := "example.com"
    // Instantiate a new Browser.
    // The first argument is the URL to analyze.
    // The second argument is the path to the file where to save the screenshot.
    // Through the third argument we can specify a proxy to route the browser through.
    // (for example "socks5://127.0.0.1:9050" for Tor).
    // The fourth argument indicates whether to log all DevTools Protocol events.
    // Through the fifth argument we can indicate a different Docker image that
    // isn't the default.
    b := browser.New(url, "/path/to/screen.png", "", false, "")
    // Run the browser.
    b.Run()

    // Now we analyze the results.
    a := phishdetect.NewAnalysis(url, b.HTML)
    a.AnalyzeURL()
    // Analyze the HTML string.
    a.AnalyzeBrowserResults(b)
    brand := a.Brands.GetBrand()

    // In addition to the results explained in the previous example, we have
    // soma additional information provided by the browser execution.
    // FinalURL will show the last visited URL by the browser. This might differ
    // from the original URL if the browser was redirected.
    fmt.Println(b.FinalURL)

    // Visits contains a list of all the URLs visited by the browser.
    // Normally 302 redirects or JavaScript redirects should appear (although in
    // the latter case, some might not appear if it took to long to load.)
    for _, visit := range b.Visits {
        fmt.Println(visit)
    }

    // In addition to the URL analysis warnings, we should also have any matched
    // HTML analysis warnings.
}
```

For more information, please refer to the [reference documentation](https://pkg.go.dev/github.com/phishdetect/phishdetect).


### Adding new Brands to the existing list

PhishDetect comes pre-compiled with a fixed set of brands. You might want to load custom ones from external sources. You can easily do so when creating a new `Analysis`.

```go
import (
    "github.com/phishdetect/phishdetect"
    "github.com/phishdetect/phishdetect/brands"
)

func main() {
    // We create a new Brand.
    myBrand := brands.Brand{
        Name:       "MyBrand",
        Original:   []string{"MyBrand", "MyBrandProduct"},
        Safelist:   []string{"mybrand.com", "mybrand.net", "mybrand.org"},
        Suspicious: []string{"mybland.com", "mybrend.com", "mgbrand.com"},
    }

    // We instantiate a new analysis.
    a := phishdetect.NewAnalysis("example.com", "")
    // We access the list of brands from the current analysis and add a new one.
    a.Brands.AddBrand(myBrand)
    // Finally, we analyze the domain.
    a.AnalyzeURL()
}
```


### Adding Yara rules to the HTML classifier

If you want to scan the visited page's HTML with Yara rules of your own, you just need to initialize PhishDetect's scanner using `phishdetect.LoadYaraRules()` and by providing the path (as a `string`) to either a Yara rule file or a folder containing Yara rule files (with `.yar` or `.yara` extensions).

For example:

```go
err := phishdetect.LoadYaraRules(rulesPath)
if err != nil {
    log.Error("I failed to initialize the Yara scanner: ", err.Error())
}
```

This needs to be done only once (perhaps in your program's `init()` function). All following analysis will make use of the same initialized scanner.



## Using PhishDetect CLI

Firstly, make sure you have Go 1.11+ installed. We require Go 1.11 or later versions because of the native support for Go Modules, which we use to manage dependencies. If it isn't available for your operating system of choice, we recommend trying [gvm](https://github.com/moovweb/gvm).

Or build the binary from the source code. In order to do so, proceed cloning the Git repository:

    $ git clone github.com/phishdetect/phishdetect.git

In order to build binaries for GNU/Linux:

    $ make

Once the compilation is completed, you will find the command-line interface in the `build/` folder.

Launch `phishdetect -h` to view the help message:

    Usage of phishdetect:
          --api-version string    Specify which Docker API version to use (default "1.37")
          --brands string         Specify a folder containing YAML files with Brand specifications
          --container string      Specify a name for a docker image to use (default "phishdetect/phishdetect")
          --debug                 Enable debug logging
          --html string           Specify a path to save the HTML from the visited page
          --log-events            Log all DevTools events
          --print-visits          Print JSON output of all visits
          --proxy string          Route connection through a SOCKS5 proxy
          --safebrowsing string   Specify a file path containing your Google SafeBrowsing API key
          --screen string         Specify the file path to store the screenshot
          --url-only              Only perform URL analysis
          --yara string           Specify a path to a file or folder contaning Yara rules


## License

PhishDetect is released under GNU Affero General Public License 3.0 and is copyrighted to Claudio Guarnieri.
