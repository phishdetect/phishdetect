// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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

package brands

import (
	"regexp"

	"github.com/phishdetect/phishdetect/utils"
)

// Brands defines the attribute of our list of supported brands.
type Brands struct {
	Top  *Brand
	List []*Brand
}

// New instantiates a new Brands struct.
func New() *Brands {
	return &Brands{
		Top: nil,
		List: []*Brand{
			Amazon(),
			Apple(),
			Coinbase(),
			Docusign(),
			Dropbox(),
			Facebook(),
			Google(),
			Instagram(),
			Linkedin(),
			Microsoft(),
			Netflix(),
			NYTimes(),
			PayPal(),
			ProtonMail(),
			RiseUp(),
			Skype(),
			Slack(),
			Spotify(),
			Telegram(),
			Tutanota(),
			Twitter(),
			WhatsApp(),
			Yahoo(),
		},
	}
}

// AddBrand adds a new brand to the list.
func (b *Brands) AddBrand(brand *Brand) {
	b.List = append(b.List, brand)
}

// GetBrand determines which among the marked brands is most likely
// the one impersonated by the page.
func (b *Brands) GetBrand() string {
	for _, brand := range b.List {
		if brand.Matches <= 0 {
			continue
		}
		if b.Top == nil {
			b.Top = brand
			continue
		}
		if brand.Matches > b.Top.Matches {
			b.Top = brand
		}
	}

	if b.Top != nil {
		return b.Top.Name
	}

	return ""
}

// IsDomainSafelisted checks if the specified domain is in any of the safelists
// of the supported brands.
func (b *Brands) IsDomainSafelisted(domain, brandName string) bool {
	for _, brand := range b.List {
		if brandName != "" && brandName != brand.Name {
			continue
		}

		for _, safelist := range brand.Safelist {
			if domain == safelist {
				// Because the domain seems safelisted, we just add a large value
				// to the Matches attribute, to make sure we brand the domain right.
				brand.Matches += 100
				return true
			}
		}
	}

	return false
}

// IsLinkDangerous checks if the specified link matches a brand's dangerous
// regexp.
func (b *Brands) IsLinkDangerous(link, brandName string) bool {
	for _, brand := range b.List {
		if brandName != "" && brandName != brand.Name {
			continue
		}

		for _, dangerous := range brand.Dangerous {
			match, _ := regexp.MatchString(dangerous, utils.NormalizeURL(link))
			if match {
				return true
			}
		}
	}

	return false
}
