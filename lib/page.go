package phishdetect

import (
	"fmt"
	"github.com/anaskhan96/soup"
	"jaytaylor.com/html2text"
	"strings"
)

// Page contains information on the HTML page.
type Page struct {
	HTML string
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
func (p *Page) GetEntities(entity string) []soup.Root {
	return p.Soup.FindAll(entity)
}
