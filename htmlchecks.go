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

package phishdetect

import (
	"fmt"
	"github.com/mozillazg/go-unidecode"
	"regexp"
	"strings"
)

func checkSuspiciousTitle(link *Link, page *Page, brands *Brands) bool {
	title := page.GetTitle()
	if strings.TrimSpace(title) == "" {
		return false
	}

	// TODO: Need to add unicode conversion for comparison.
	for _, brand := range brands.List {
		expr := fmt.Sprintf("(?i)%s", strings.Join(brand.Original, "|"))
		regex, _ := regexp.Compile(expr)
		if regex.MatchString(title) {
			brand.Matches++
			return true
		}
	}

	return false
}

func checkEscapedText(link *Link, page *Page, brands *Brands) bool {
	for _, brand := range brands.List {
		for _, keyword := range brand.Original {
			// We do this because by default we would just check for "apple".
			// While still not ideal, at least now we check for "apple" and "Apple".
			variations := []string{
				keyword,
				strings.Title(keyword),
			}
			for _, variation := range variations {
				entities := []string{}
				for _, c := range variation {
					entities = append(entities, fmt.Sprintf("&#%d;", int(c)))
				}
				escaped := strings.Join(entities, "")

				if TextContains(page.HTML, escaped) {
					brand.Matches++
					return true
				}

				entitiesHex := []string{}
				for _, c := range variation {
					entitiesHex = append(entitiesHex, fmt.Sprintf("&#%x;", int(c)))
				}
				escapedHex := strings.Join(entitiesHex, "")

				if TextContains(page.HTML, escapedHex) {
					brand.Matches++
					return true
				}
			}
		}
	}

	return false
}

func checkEncodedText(link *Link, page *Page, brands *Brands) bool {
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
				return true
			}
		}
	}

	return false
}

// This is mostly used for brand identification.
// We actually give it a score of 0, so that it doesn't influence classification.
func checkBrandOriginal(link *Link, page *Page, brands *Brands) bool {
	for _, brand := range brands.List {
		for _, keyword := range brand.Original {
			if TextContains(page.Text, keyword) {
				brand.Matches++
				return true
			}
		}
	}

	return false
}

func checkSuspiciousText(link *Link, page *Page, brands *Brands) bool {
	// TODO: Need to move these in brands.
	patterns := []string{
		"continue to Google Drive",
		"Select Email Provider",
		"Sign in with your email",
		"Sign in with Gmail",
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
	}

	for _, pattern := range patterns {
		if TextContains(page.Text, pattern) {
			return true
		}
	}

	return false
}

func checkTwoFactor(link *Link, page *Page, brands *Brands) bool {
	patterns := []string{
		"2-Step Verification",
		"verification code was just sent to your number",
	}

	for _, pattern := range patterns {
		if TextContains(page.Text, pattern) {
			return true
		}
	}

	return false
}

func checkPasswordInput(link *Link, page *Page, brands *Brands) bool {
	inputs := page.GetInputs("password")
	if len(inputs) > 0 {
		return true
	}
	return false
}

func checkHiddenInput(link *Link, page *Page, brands *Brands) bool {
	inputs := page.GetInputs("hidden")
	if len(inputs) > 0 {
		return true
	}
	return false
}

func checkDecrypt(link *Link, page *Page, brands *Brands) bool {
	exprs := []string{
		"(?i)aes\\.ctr\\.decrypt\\(",
		"(?i)cryptojs\\.aes\\.decrypt\\(",
	}
	for _, expr := range exprs {
		regex, _ := regexp.Compile(expr)
		if regex.MatchString(page.HTML) {
			return true
		}
	}

	return false
}

func checkNoIndexRobots(link *Link, page *Page, brands *Brands) bool {
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
		return true
	}

	return false
}

func checkSigninData(link *Link, page *Page, brands *Brands) bool {
	dataStrings := []string{
		"data-initial-sign-in-data",
		"data-initial-setup-data",
		"data-app-config",
	}
	for _, data := range dataStrings {
		if TextContains(page.HTML, data) {
			return true
		}
	}

	return false
}

func checkPHPFormAction(link *Link, page *Page, brands *Brands) bool {
	forms := page.GetEntities("form")
	for _, form := range forms {
		attrs := form.Attrs()
		if _, ok := attrs["action"]; !ok {
			continue
		}

		action := strings.ToLower(attrs["action"])
		if strings.HasSuffix(action, ".php") {
			return true
		}
	}

	return false
}

func checkIFrameWithPHP(link *Link, page *Page, brands *Brands) bool {
	iframes := page.GetEntities("iframe")
	for _, iframe := range iframes {
		attrs := iframe.Attrs()
		if _, ok := attrs["src"]; !ok {
			continue
		}

		src := strings.ToLower(attrs["src"])
		if strings.HasSuffix(src, ".php") {
			return true
		}
	}

	return false
}

func checkMultiAuth(link *Link, page *Page, brands *Brands) bool {
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
		return true
	}

	return false
}

// GetHTMLChecks returns a list of all the available HTML checks.
func GetHTMLChecks() []Check {
	return []Check{
		{
			checkBrandOriginal,
			0,
			"brand-original",
			"The page contains mentions of original brand names (e.g. \"Google\", \"Facebook\", etc.)",
		},
		{
			checkHiddenInput,
			5,
			"hidden-input",
			"The page contains an hidden input",
		},
		{
			checkPasswordInput,
			10,
			"password-input",
			"The page contains a password input",
		},
		{
			checkNoIndexRobots,
			10,
			"noindex",
			"The page explicitly forbids search sites to index it",
		},
		{
			checkIFrameWithPHP,
			15,
			"php-iframe",
			"The page contains a frame loading a PHP page",
		},
		{
			checkSigninData,
			20,
			"signin-data",
			"The page contains sign-in data, suggesting it is a clone",
		},
		{
			checkSuspiciousTitle,
			20,
			"suspicious-title",
			"The page has a suspicious title",
		},
		{
			checkTwoFactor,
			20,
			"two-factor",
			"The page may attempt to steal the two-factor authentication token",
		},
		{
			checkDecrypt,
			20,
			"decrypt",
			"The page contains decryption routines",
		},
		{
			checkPHPFormAction,
			20,
			"php-form",
			"The page contains a form pointing to a PHP script",
		},
		{
			checkMultiAuth,
			20,
			"multi-auth",
			"The page appears to offer multiple sign-in options",
		},
		{
			checkSuspiciousText,
			25,
			"suspicious-text",
			"The page contains suspicious text",
		},
		{
			checkEscapedText,
			25,
			"escaped-text",
			"The page is escaping brand words with HTML entities to evade detection",
		},
		{
			checkEncodedText,
			25,
			"encoded-text",
			"The page is obfuscating brand words to evade detection",
		},
	}
}
