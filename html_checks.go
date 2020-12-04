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
	"fmt"
	"regexp"
	"strings"

	"github.com/hillu/go-yara/v4"
	"github.com/mozillazg/go-unidecode"
)

type CheckTarget struct {
	Type       string
	Identifier string
	Content    string
}

// getCheckTargets is used to build a collection of check targets for those
// checks that require scanning the DOM HTML and downloaded resources.
func getCheckTargets(page *Page, resourcesData ResourcesData) []CheckTarget {
	var targets []CheckTarget
	targets = append(targets, CheckTarget{
		Type:       "html",
		Identifier: page.SHA256,
		Content:    page.HTML,
	})
	for _, resource := range resourcesData {
		targets = append(targets, CheckTarget{
			Type:       "resource",
			Identifier: resource.SHA256,
			Content:    resource.Content,
		})
	}
	return targets
}

// checkSuspiciousTitle determines if the page title contains any references
// to any brand's name.
func checkSuspiciousTitle(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	title := page.GetTitle()
	if strings.TrimSpace(title) == "" {
		return false, nil
	}

	// TODO: Need to add unicode conversion for comparison.
	for _, brand := range brands.List {
		expr := fmt.Sprintf("(?i)%s", strings.Join(brand.Original, "|"))
		regex, _ := regexp.Compile(expr)
		if regex.MatchString(title) {
			// Having the brand name in the title is a stronger indication.
			brand.Matches += 3
			return true, map[string]string{
				"title": title,
			}
		}
	}

	return false, nil
}

// checkEscapedText determines if the page contains any HTML escaped versions
// of any brand's name.
func checkEscapedText(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	// For each brand ...
	for _, brand := range brands.List {
		// ... we check whether there are HTML escaped versions of the
		// brand's name or the name of its products and services.
		for _, keyword := range brand.Original {
			// We do this because by default we would just check for "apple".
			// While still not ideal, at least now we check for "apple" and "Apple".
			variations := []string{
				keyword,
				strings.Title(keyword),
			}
			for _, variation := range variations {
				// First we try using a decimal escape.
				entities := []string{}
				for _, c := range variation {
					entities = append(entities, fmt.Sprintf("&#%d;", int(c)))
				}
				escaped := strings.Join(entities, "")

				if TextContains(page.HTML, escaped) {
					brand.Matches++
					return true, nil
				}

				// Then we try an hexadecimal escape.
				entitiesHex := []string{}
				for _, c := range variation {
					entitiesHex = append(entitiesHex, fmt.Sprintf("&#%x;", int(c)))
				}
				escapedHex := strings.Join(entitiesHex, "")

				if TextContains(page.HTML, escapedHex) {
					brand.Matches++
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// checkEncodedText determines if the page contains any Unicode encoded
// versions of any brand's name.
func checkEncodedText(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	for _, brand := range brands.List {
		for _, keyword := range brand.Original {
			// First we check if the keyword already is found in "clear".
			// If so, we have to skip it.
			if TextContains(page.Text, keyword) {
				continue
			}

			decoded := unidecode.Unidecode(page.Text)
			if TextContains(decoded, keyword) {
				brand.Matches++
				return true, nil
			}
		}
	}

	return false, nil
}

// checkBrandOriginal just checks if the page contains any brand's name.
// This is mostly used for brand identification, so we give it a score of 0.
// This check doesn't influence classification.
func checkBrandOriginal(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	for _, brand := range brands.List {
		for _, keyword := range brand.Original {
			if TextContains(page.Text, keyword) {
				brand.Matches++
				return true, nil
			}
		}
	}

	return false, nil
}

// checkSuspiciousText determines if the page contains any common strings
// used in phishing pages.
func checkSuspiciousText(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	// TODO: Need to move these in brands.
	patterns := []string{
		"continue to Google Drive",
		"Select Email Provider",
		"Sign in with your email",
		"Sign in with Gmail",
		"Sign in to your account",
		"Share files from Google Drive",
		"A better way to share Documents",
		"Sign in to view attachment",
		"Sign in to view the file shared with you",
		"Sign in with your email address to view or download attachment",
		"you can sign in to dropbox with your email",
		"OneDrive works with all email domain",
		"Manage your Apple account",
		"Your account for everything Apple",
		"Sign in to iCloud",
		"Login with Facebook",
		"please choose your email provider",
		"Login to view shared file",
		"If you've signed in to Google products like YouTube, try again with that email",
		"Couldn't find your Google Account",
		"Forgot Apple ID or password",
		"Receive Secure cloud files",
		"Any e-mail, Anywhere!",
		"еmаіl аddrеss аs а bасkuр fοr thеіr Yаhοο Ассοunt",
		"Dіsсοnnесt уοur еmаіl аddrеss",
		"Sign in With Your Existing Email",
		"Put your creative energy to work, with Dropbox",
		"Your account or password is incorrect",
		"Forgot my password",
	}

	for _, pattern := range patterns {
		if TextContains(page.Text, pattern) {
			return true, nil
		}

		if TextContains(page.HTML, pattern) {
			return true, nil
		}
	}

	return false, nil
}

// checkTwoFactor checks for the presence of strings potentially indicating
// phishing for 2FA tokens.
func checkTwoFactor(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	patterns := []string{
		"2-Step Verification",
		"verification code was just sent to your number",
	}

	for _, pattern := range patterns {
		if TextContains(page.Text, pattern) {
			return true, nil
		}
	}

	return false, nil
}

// checkPasswordInput just determines if the page contains a password
// form input.
func checkPasswordInput(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	inputs := page.GetInputs("password")
	if len(inputs) > 0 {
		return true, nil
	}
	return false, nil
}

// checkHiddenInput just determines if the page contains a hidden form input.
func checkHiddenInput(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	inputs := page.GetInputs("hidden")
	if len(inputs) > 0 {
		return true, nil
	}
	return false, nil
}

// checkDecrypt determines if the page contains what appear to be JavaScript
// decryption routines.
func checkDecrypt(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	exprs := []string{
		"(?i)aes\\.ctr\\.decrypt\\(",
		"(?i)cryptojs\\.aes\\.decrypt\\(",
	}

	targets := getCheckTargets(page, resourcesData)
	for _, expr := range exprs {
		regex, _ := regexp.Compile(expr)

		for _, target := range targets {
			if regex.MatchString(target.Content) {
				return true, map[string]string{
					"entity": target.Type,
					"identifier": target.Identifier,
					"matched_regexp": expr,
				}
			}
		}
	}

	return false, nil
}

// checkDocumentWrite determines whether the page is being built dynamically
// using document.write() JavaScript function (which is rather atypical for
// legitimate modern web tech).
func checkDocumentWrite(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	exprs := []string{
		"(?i)document\\.write\\(",
	}

	targets := getCheckTargets(page, resourcesData)
	for _, expr := range exprs {
		regex, _ := regexp.Compile(expr)

		for _, target := range targets {
			if regex.MatchString(target.Content) {
				return true, map[string]string{
					"entity": target.Type,
					"identifier": target.Identifier,
					"matched_regexp": expr,
				}
			}
		}
	}

	return false, nil
}

// checkNoIndexRobots determines if the page has any meta tags to disable
// archiving and indexing by search engines.
func checkNoIndexRobots(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	robots := []string{
		"noarchive",
		"noindex",
		"noimageindex",
		"nofollow",
	}
	counter := 0

	metas := page.GetEntities("meta")
	for _, meta := range metas {
		attrs := meta.Attrs()
		if _, ok := attrs["content"]; !ok {
			continue
		}

		content := strings.ToLower(attrs["content"])
		for _, robot := range robots {
			robot = strings.ToLower(robot)
			if strings.Contains(content, robot) {
				counter++
			}
		}
	}

	if counter >= 2 {
		return true, nil
	}

	return false, nil
}

// checkSigninData determines if the page contains HTML data attributes,
// which might indicate that the page (if not legitimate) was mirrored from
// e.g. Google's login page.
func checkSigninData(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	dataStrings := []string{
		"data-initial-sign-in-data",
		"data-initial-setup-data",
		"data-app-config",
	}
	for _, data := range dataStrings {
		if TextContains(page.HTML, data) {
			return true, nil
		}
	}

	return false, nil
}

// checkPHPFormAction just determines if the page contains a form pointing
// to a PHP page.
func checkPHPFormAction(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	forms := page.GetEntities("form")
	for _, form := range forms {
		attrs := form.Attrs()
		if _, ok := attrs["action"]; !ok {
			continue
		}

		action := strings.Split(strings.ToLower(attrs["action"]), "?")[0]
		if strings.HasSuffix(action, ".php") {
			return true, map[string]string{
				"form_action": action,
			}
		}
	}

	return false, nil
}

// checkIFrameWithPHP just determines if the page contains an iframe loading
// a PHP script.
func checkIFrameWithPHP(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	iframes := page.GetEntities("iframe")
	for _, iframe := range iframes {
		attrs := iframe.Attrs()
		if _, ok := attrs["src"]; !ok {
			continue
		}

		src := strings.Split(strings.ToLower(attrs["src"]), "?")[0]
		if strings.HasSuffix(src, ".php") {
			return true, map[string]string{
				"iframe_src": src,
			}
		}
	}

	return false, nil
}

// checkMultiAuth determines if the page is attempting to phish for
// multiple email services at once.
func checkMultiAuth(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	// TODO: Hacky, replace with regexps.
	patterns := []string{
		"Sign in with Google",
		"Sign in with Yahoo",
		"Sign in with Outlook",
		"Sign in with Twitter",
		"Sign in with Facebook",
		"Sign in with other emails",
		"Sign in with other email",
		"Sign in with other mails",
		"Sign in with other mail",
		"Sign in with AOL",
		"Login with Google",
		"Login with Yahoo",
		"Login with Outlook",
		"Login with Twitter",
		"Login with Facebook",
		"Login with AOL",
		"Login with other emails",
		"Login with other email",
		"Login with other mails",
		"Login with other mail",
	}

	counter := 0
	for _, pattern := range patterns {
		if TextContains(page.Text, pattern) {
			counter++
		}
	}

	if counter >= 3 {
		return true, nil
	}

	return false, nil
}

func checkYaraRules(link *Link, page *Page, resourcesData ResourcesData, brands *Brands) (bool, interface{}) {
	if YaraRules == nil {
		return false, nil
	}

	targets := getCheckTargets(page, resourcesData)

	for _, target := range targets {
		var matches yara.MatchRules
		err := YaraRules.ScanMem([]byte(target.Content), 0, 30, &matches)
		if err != nil {
			continue
		}

		if len(matches) == 0 {
			continue
		}
		for _, match := range matches {
			// If the rule does not contain a "brand" meta value, we skip.
			matchBrand := ""
			for _, meta := range match.Metas {
				if meta.Identifier == "brand" {
					matchBrand = meta.Value.(string)
					break
				}
			}
			if matchBrand == "" {
				continue
			}
			for _, brand := range brands.List {
				// If we have a match on an existing brand, we increase the
				// Matches value.
				if brand.Name == strings.ToLower(matchBrand) {
					brand.Matches += 50
					break
				}
			}
		}

		return true, map[string]interface{}{
			"entity":     target.Type,
			"identifier": target.Identifier,
			"matches":    matches,
		}
	}

	return false, nil
}

// GetHTMLChecks returns a list of all the available HTML checks.
func GetHTMLChecks() []Check {
	return []Check{
		{
			Call:        checkBrandOriginal,
			Score:       0,
			Name:        "brand-original",
			Description: "The page contains mentions of original brand names (e.g. \"Google\", \"Facebook\", etc.)",
		},
		{
			Call:        checkHiddenInput,
			Score:       5,
			Name:        "hidden-input",
			Description: "The page contains an hidden input",
		},
		{
			Call:        checkPasswordInput,
			Score:       10,
			Name:        "password-input",
			Description: "The page contains a password input",
		},
		{
			Call:        checkNoIndexRobots,
			Score:       10,
			Name:        "noindex",
			Description: "The page explicitly forbids search sites to index it",
		},
		{
			Call:        checkDocumentWrite,
			Score:       10,
			Name:        "document-write",
			Description: "The page is being dynamically generated with suspicious JavaScript functions",
		},
		{
			Call:        checkIFrameWithPHP,
			Score:       15,
			Name:        "php-iframe",
			Description: "The page contains a frame loading a PHP page",
		},
		{
			Call:        checkSigninData,
			Score:       20,
			Name:        "signin-data",
			Description: "The page contains sign-in data, suggesting it is a clone",
		},
		{
			Call:        checkSuspiciousTitle,
			Score:       20,
			Name:        "suspicious-title",
			Description: "The page has a suspicious title",
		},
		{
			Call:        checkTwoFactor,
			Score:       20,
			Name:        "two-factor",
			Description: "The page may attempt to steal the two-factor authentication token",
		},
		{
			Call:        checkDecrypt,
			Score:       20,
			Name:        "decrypt",
			Description: "The page contains decryption routines",
		},
		{
			Call:        checkPHPFormAction,
			Score:       20,
			Name:        "php-form",
			Description: "The page contains a form pointing to a PHP script",
		},
		{
			Call:        checkMultiAuth,
			Score:       20,
			Name:        "multi-auth",
			Description: "The page appears to offer multiple sign-in options",
		},
		{
			Call:        checkSuspiciousText,
			Score:       25,
			Name:        "suspicious-text",
			Description: "The page contains suspicious text",
		},
		{
			Call:        checkEscapedText,
			Score:       25,
			Name:        "escaped-text",
			Description: "The page is escaping brand words with HTML entities to evade detection",
		},
		{
			Call:        checkEncodedText,
			Score:       25,
			Name:        "encoded-text",
			Description: "The page is obfuscating brand words to evade detection",
		},
		{
			Call:        checkYaraRules,
			Score:       50,
			Name:        "yara-rule",
			Description: "The page or a loaded resource matched a Yara rule",
		},
	}
}
