package phishdetect

import (
	"github.com/phishdetect/phishdetect/lib/brand"
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
			brand.Telegram(),
			brand.Tutanota(),
			brand.Twitter(),
			brand.WhatsApp(),
			brand.Yahoo(),
		},
	}
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

// IsDomainWhitelisted checks if the specified domain is in any of the whitelists
// of the supported brands.
func (b *Brands) IsDomainWhitelisted(domain, brandName string) bool {
	for _, brand := range b.List {
		if brandName != "" && brandName != brand.Name {
			continue
		}

		for _, whitelist := range brand.Whitelist {
			if domain == whitelist {
				// Because the domain seems whitelisted, we just add a large value
				// to the Matches attribute, to make sure we brand the domain right.
				brand.Matches += 100
				return true
			}
		}
	}

	return false
}
