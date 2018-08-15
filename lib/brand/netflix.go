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

// Netflix brand properties.
func Netflix() *Brand {
	name := "netflix"
	original := []string{"netflix"}
	whitelist := []string{
		"netflix.adult", "netflix.af", "netflix.ag", "netflix.ai",
		"netflix.asia", "netflix.at", "netflix-australia.com", "netflix.ax",
		"netflix.berlin", "netflix.bg", "netflix.bi", "netflix.buzz",
		"netflix.bz", "netflix.cat", "netflix.cc", "netflix.ceo", "netflix.cf",
		"netflix.club", "netflix.cm", "netflix.cn", "netflix.co",
		"netflix.co.ag", "netflix.co.at", "netflix.co.bi", "netflix.co.bw",
		"netflix.co.cm", "netflix.co.gl", "netflix.co.gy", "netflix.co.in",
		"netflix.co.ke", "netflix.co.kr", "netflix.co.lc", "netflix.com",
		"netflix.com.af", "netflix.com.ag", "netflix.com.ai", "netflix.com.bi",
		"netflix.com.bz", "netflix.com.cm", "netflix.com.cn", "netflix.com.co",
		"netflix.com.de", "netflix.com.ec", "netflix.com.gl", "netflix.com.gp",
		"netflix.com.gt", "netflix.com.gy", "netflix.com.hk", "netflix.com.hn",
		"netflix.com.ht", "netflix-com.ie", "netflix.com.lc", "netflix.com.lv",
		"netflix.com.ly", "netflix.com.mg", "netflix.com.ms", "netflix.com.mw",
		"netflix.com.ng", "netflix.com.pa", "netflix.com.pe", "netflix.com.pr",
		"netflix.com.ps", "netflix.com.sb", "netflix.com.sc", "netflix.com.sg",
		"netflix.com.sl", "netflix.com.sn", "netflix.com.tj", "netflix.com.tw",
		"netflix.com.ua", "netflix-com.uk", "netflix.com.vc", "netflix.com.vi",
		"netflix.co.mw", "netflix.co.nz", "netflix.co.pn", "netflix.co.tj",
		"netflix.co.tz", "netflix.co.ug", "netflix.co.vi", "netflix.co.za",
		"netflix-customerservice.com", "netflix.cx", "netflix.cz", "netflix.de",
		"netflix.ec", "netflix.film", "netflix.firm.in", "netflix.fm",
		"netflix-forever.de", "netflix.fr", "netflix.ga", "netflix.gd",
		"netflix.gen.in", "netflix.gl", "netflix.gp", "netflix.gq",
		"netflix.gs", "netflix.gy", "netflix.hk", "netflix.hn", "netflix.horse",
		"netflix.ht", "netflix.id", "netflix.in", "netflix-inc.com",
		"netflix.ind.in", "netflix.info", "netflix.jobs", "netflix.jp",
		"netflix.ki", "netflix.kn", "netflix.kr", "netflix.kz", "netflix.la",
		"netflix.lc", "netflix.lu", "netflix.ly", "netflix.md", "netflix.mg",
		"netflix.ml", "netflix.mn", "netflix-service.com",
		"netflix-theater.com", "netflix-theatre.com", "netflix.net",
		"netflix.org",
	}
	suspicious := []string{
		"netflixa", "netflixb", "netflixc", "netflixd", "netflixe", "netflixf",
		"netflixg", "netflixh", "netflixi", "netflixj", "netflixk", "netflixl",
		"netflixm", "netflixn", "netflixo", "netflixp", "netflixq", "netflixr",
		"netflixs", "netflixt", "netflix", "netflixv", "netflixw", "netflixx",
		"netflixy", "netflixz", "oetflix", "letflix", "jetflix", "fetflix",
		"ndtflix", "ngtflix", "natflix", "nmtflix", "nutflix", "neuflix",
		"nevflix", "nepflix", "nedflix", "ne4flix", "netglix", "netdlix",
		"netblix", "netnlix", "netvlix", "netfmix", "netfnix", "netfhix",
		"netfdix", "netflhx", "netflkx", "netflmx", "netflax", "netflyx",
		"netfliy", "netfliz", "netflip", "netflih", "netfli8", "xn--netlix-y7f",
		"xn--netfli-gfg", "xn--netlix-5tb", "xn--neflix-j1e", "xn--netflx-7r6v",
		"xn--ntflix-bhg", "xn--etflix-heb", "xn--ntflix-iye", "netfllx",
		"xn--netflx-08a", "xn--ntflix-b5a", "xn--netflx-7va", "xn--netflx-m6b",
		"xn--netfix-6db", "xn--netfli-n77b", "retflix", "xn--ntflix-33a",
		"xn--ntflix-i4a", "xn--ntflix-bva", "metflix", "xn--neflix-qkb",
		"xn--ntflix-pva", "xn--ntflix-iva", "xn--ntflix-w4a", "xn--neflix-qrf",
		"xn--ntflix-3of", "xn--netfix-l2c", "xn--netfli-gsf", "netfl1x",
		"xn--ntflix-bvf", "xn--ntflix-p3a", "xn--netflx-71c", "xn--netlix-k6e",
		"xn--ntflix-ph8b", "netfiix", "xn--netflx-fze", "xn--netflx-t9a",
		"xn--netflx-m91a", "netf1ix", "xn--netflx-mwa", "n-etflix", "ne-tflix",
		"net-flix", "netf-lix", "netfl-ix", "netfli-x", "netzflix", "netyflix",
		"ne4tflix", "netflmix", "netvflix", "netfmlix", "newtflix", "netfli8x",
		"neytflix", "n3etflix", "netfl9ix", "netfl8ix", "nertflix", "nedtflix",
		"netfflix", "negtflix", "netfdlix", "nestflix", "ne5tflix", "netflijx",
		"ndetflix", "netfvlix", "netfolix", "netcflix", "netftlix", "ne6tflix",
		"netfli9x", "netfglix", "netflpix", "neztflix", "neftflix", "netfplix",
		"netrflix", "nettflix", "net6flix", "netfluix", "nsetflix", "netflkix",
		"nzetflix", "nwetflix", "netdflix", "nretflix", "ne3tflix", "netfrlix",
		"netfljix", "netflikx", "netfclix", "netfklix", "net5flix", "netgflix",
		"netfliux", "n4etflix", "netfloix", "netfliox", "etflix", "netlix",
		"netfli", "netfix", "neflix", "ntflix", "netflx", "netfliix",
		"neetflix", "nnetflix", "netfllix", "n3tflix", "ne6flix", "ne5flix",
		"nettlix", "nefflix", "netfljx", "netclix", "nwtflix", "netrlix",
		"nezflix", "negflix", "netflis", "netfl8x", "netfoix", "netfpix",
		"hetflix", "nztflix", "netflux", "nstflix", "netfl9x", "netflox",
		"netfkix", "betflix", "nerflix", "netflic", "nrtflix", "n4tflix",
		"neyflix", "netflid", "n.etflix", "ne.tflix", "net.flix", "netf.lix",
		"netfl.ix", "netfli.x", "entflix", "nteflix", "neftlix", "netlfix",
		"netfilx", "netflxi", "nitflix", "notflix", "netflex", "netflixcom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
