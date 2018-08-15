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

package brand

// Skype brand properties.
func Skype() *Brand {
	name := "skype"
	original := []string{"skype"}
	whitelist := []string{"skype.com", "skype.net", "skype.org"}
	suspicious := []string{
		"3kype", "sjype", "siype", "soype", "scype", "skxpe", "skqpe", "skipe",
		"sk9pe", "skyqe", "skyre", "skyte", "skyxe", "sky0e", "skypd", "skypg",
		"skypa", "skypm", "skyp", "xn--kype-uv0c", "xn--skye-i6d",
		"xn--skpe-w6d", "xn--skpe-mfc", "xn--skyp-opa", "xn--skyp-jpa",
		"xn--skye-dsa", "xn--skyp-epa", "xn--kype-f9d", "xn--skyp-e9d",
		"xn--skpe-cne", "xn--skyp-omd", "xn--skpe-6ra", "xn--skye-xkb",
		"slkype", "xn--kype-k5a", "xn--skye-dod", "xn--skyp-y4d",
		"xn--skyp-ou5a", "xn--skye-7vd", "xn--skyp-epe", "xn--sype-gc0c",
		"sikype", "xn--sype-bnd", "xn--skyp-eva", "xn--skyp-yva", "slcype",
		"xn--skyp-ova", "xn--skyp-jwa", "xn--skyp-8va", "xn--kype-zh",
		"xn--skpe-cmd", "xn--kype-pdc", "s-kype", "sk-ype", "sky-pe", "skyp-e",
		"smkype", "sk6ype", "sjkype", "skiype", "skxype", "sokype", "skmype",
		"skypme", "skjype", "skypoe", "skyple", "skyxpe", "skoype", "sksype",
		"skygpe", "sky7pe", "sklype", "skyspe", "skyhpe", "skyape", "skyp0e",
		"skyope", "skhype", "skgype", "skympe", "sk7ype", "skylpe", "sky6pe",
		"skuype", "sktype", "skaype", "skyupe", "skytpe", "sky0pe", "kype",
		"skpe", "skyp", "sype", "skyype", "sskype", "skyppe", "skkype", "skypr",
		"skyoe", "skyps", "skypz", "zkype", "akype", "sk7pe", "skape", "sktpe",
		"slype", "skupe", "skspe", "skhpe", "xkype", "skyle", "skyp4", "skypw",
		"skgpe", "skyp3", "sk6pe", "ekype", "smype", "ykype", "dkype", "s.kype",
		"sk.ype", "sky.pe", "skyp.e", "ksype", "sykpe", "skpye", "skyep",
		"skypi", "skypo", "skypecom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
