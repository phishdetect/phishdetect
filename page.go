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
	"strings"

	"github.com/anaskhan96/soup"
	"jaytaylor.com/html2text"
)

// Page contains information on the HTML page.
type Page struct {
	HTML string
	SHA256 string
	Soup soup.Root
	Text string
}

// NewPage instantiates a new Page struct.
func NewPage(html string) (*Page, error) {
	if strings.TrimSpace(html) == "" {
		return nil, fmt.Errorf("No valid HTML provided")
	}

	soup := soup.HTMLParse(html)
	text, _ := html2text.FromString(html, html2text.Options{
		PrettyTables: false,
	})

	return &Page{
		HTML: html,
		SHA256: GetSHA256Hash(html),
		Soup: soup,
		Text: text,
	}, nil
}

// GetTitle returns the content of the <title> tag from the HTML page.
func (p *Page) GetTitle() string {
	title := p.Soup.Find("title")
	if title.Error != nil {
		return ""
	}
	return title.Text()
}

// GetInputs returns any form input.
func (p *Page) GetInputs(inputType string) []soup.Root {
	return p.Soup.FindAll("input", "type", inputType)
}

// GetEntities returns any HTML entity of the specified type.
func (p *Page) GetEntities(entityType string) []soup.Root {
	return p.Soup.FindAll(entityType)
}
