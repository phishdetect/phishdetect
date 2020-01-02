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
	"github.com/phishdetect/phishdetect/brand"
)

// Brands defines the attribute of our list of supported brands.
type Brands struct {
	Top  *brand.Brand
	List []*brand.Brand
}

// NewBrands instantiates a new Brands struct.
func NewBrands() *Brands {
	return &Brands{
		Top: nil,
		List: []*brand.Brand{
			brand.Amazon(),
			brand.Apple(),
			brand.Coinbase(),
			brand.Docusign(),
			brand.Dropbox(),
			brand.Facebook(),
			brand.Google(),
			brand.Instagram(),
			brand.Linkedin(),
			brand.Microsoft(),
			brand.Netflix(),
			brand.NYTimes(),
			brand.PayPal(),
			brand.ProtonMail(),
			brand.RiseUp(),
			brand.Skype(),
			brand.Slack(),
			brand.Spotify(),
			brand.Telegram(),
			brand.Tutanota(),
			brand.Twitter(),
			brand.WhatsApp(),
			brand.Yahoo(),
		},
	}
}

// AddBrand adds a new brand to the list.
func (b *Brands) AddBrand(brand *brand.Brand) {
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
