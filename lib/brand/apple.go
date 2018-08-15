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

// Apple brand properties.
func Apple() *Brand {
	name := "apple"
	original := []string{"apple", "appleid", "icloud", "itunes"}
	whitelist := []string{
		"apple.com", "icloud.com", "mac.com", "airport.com", "applecomputer.com",
		"appleimac.com", "imac.com", "iphone.com", "iphone.org", "ipod.com",
		"itunes.com", "applemusic.com",
	}
	suspicious := []string{
		"cpple", "epple", "ipple", "qpple", "aqple", "arple", "atple", "axple",
		"a0ple", "apqle", "aprle", "aptle", "apxle", "ap0le", "appme", "appne",
		"apphe", "appde", "appld", "applg", "appla", "applm", "appl", "aplple",
		"ampple", "apmple", "a0pple", "alpple", "appmle", "applke", "apople",
		"apploe", "applme", "appole", "appple", "appkle", "applle", "ap0ple",
		"aopple", "applpe", "app0le", "appe", "appl", "pple", "aple", "aapple",
		"spple", "apmle", "applr", "appls", "applw", "aplle", "applz", "2pple",
		"apppe", "ample", "ypple", "aople", "alple", "appl3", "appl4", "1pple",
		"zpple", "wpple", "apole", "appke", "appoe", "paple", "aplpe", "appel",
		"appli", "opple", "applo", "upple", "applecom", "xn--ale-izca",
		"xn--pple-4na", "xn--appl-epa", "xn--appl-jpa", "xn--aple-bsa",
		"xn--appl-omd", "xn--pple-koa", "xn--pple-zna", "xn--ale-poaa",
		"xn--ale-rbba", "xn--aple-csa", "xn--aple-cod", "xn--aple-6vd",
		"xn--pple-43d", "xn--aple-h6d", "xn--pple-foa", "xn--appl-e9d",
		"xn--appl-ova", "xn--aple-vkb", "xn--appl-opa", "xn--pple-4q5a",
		"xn--ale-s5ca", "xn--pple-9na", "xn--pple-pzb", "xn--aple-g6d",
		"xn--pple-zsa", "xn--appl-ou5a", "xn--aple-wkb", "xn--appl-epe",
		"app1e", "xn--pple-poa", "xn--pple-zmb", "xn--ale-0eda", "xn--pple-fse",
		"xn--aple-bod", "xn--appe-21a", "xn--appe-i9b", "xn--appl-eva",
		"xn--pple-p5b", "appie", "xn--appl-yva", "xn--aple-5vd", "xn--appl-8va",
		"xn--appl-jwa", "xn--appl-y4d", "arrle",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
