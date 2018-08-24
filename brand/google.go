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

// Google brand properties.
func Google() *Brand {
	name := "google"
	original := []string{"google", "gmail", "gdrive"}
	whitelist := []string{
		"google.com", "google.ad", "google.ae", "google.com.af",
		"google.com.ag", "google.com.ai", "google.al", "google.am",
		"google.co.ao", "google.com.ar", "google.as", "google.at",
		"google.com.au", "google.az", "google.ba", "google.com.bd", "google.be",
		"google.bf", "google.bg", "google.com.bh", "google.bi", "google.bj",
		"google.com.bn", "google.com.bo", "google.com.br", "google.bs",
		"google.bt", "google.co.bw", "google.by", "google.com.bz", "google.ca",
		"google.cd", "google.cf", "google.cg", "google.ch", "google.ci",
		"google.co.ck", "google.cl", "google.cm", "google.cn", "google.com.co",
		"google.co.cr", "google.com.cu", "google.cv", "google.com.cy",
		"google.cz", "google.de", "google.dj", "google.dk", "google.dm",
		"google.com.do", "google.dz", "google.com.ec", "google.ee",
		"google.com.eg", "google.es", "google.com.et", "google.fi",
		"google.com.fj", "google.fm", "google.fr", "google.ga", "google.ge",
		"google.gg", "google.com.gh", "google.com.gi", "google.gl", "google.gm",
		"google.gp", "google.gr", "google.com.gt", "google.gy", "google.com.hk",
		"google.hn", "google.hr", "google.ht", "google.hu", "google.co.id",
		"google.ie", "google.co.il", "google.im", "google.co.in", "google.iq",
		"google.is", "google.it", "google.je", "google.com.jm", "google.jo",
		"google.co.jp", "google.co.ke", "google.com.kh", "google.ki",
		"google.kg", "google.co.kr", "google.com.kw", "google.kz", "google.la",
		"google.com.lb", "google.li", "google.lk", "google.co.ls", "google.lt",
		"google.lu", "google.lv", "google.com.ly", "google.co.ma", "google.md",
		"google.me", "google.mg", "google.mk", "google.ml", "google.com.mm",
		"google.mn", "google.ms", "google.com.mt", "google.mu", "google.mv",
		"google.mw", "google.com.mx", "google.com.my", "google.co.mz",
		"google.com.na", "google.com.nf", "google.com.ng", "google.com.ni",
		"google.ne", "google.nl", "google.no", "google.com.np", "google.nr",
		"google.nu", "google.co.nz", "google.com.om", "google.com.pa",
		"google.com.pe", "google.com.pg", "google.com.ph", "google.com.pk",
		"google.pl", "google.pn", "google.com.pr", "google.ps", "google.pt",
		"google.com.py", "google.com.qa", "google.ro", "google.ru", "google.rw",
		"google.com.sa", "google.com.sb", "google.sc", "google.se",
		"google.com.sg", "google.sh", "google.si", "google.sk", "google.com.sl",
		"google.sn", "google.so", "google.sm", "google.sr", "google.st",
		"google.com.sv", "google.td", "google.tg", "google.co.th",
		"google.com.tj", "google.tk", "google.tl", "google.tm", "google.tn",
		"google.to", "google.com.tr", "google.tt", "google.com.tw",
		"google.co.tz", "google.com.ua", "google.co.ug", "google.co.uk",
		"google.com.uy", "google.co.uz", "google.com.vc", "google.co.ve",
		"google.vg", "google.co.vi", "google.com.vn", "google.vu", "google.ws",
		"google.rs", "google.co.za", "google.co.zm", "google.co.zw",
		"google.cat", "google.com.pt", "google.kr", "google.com.dz",
		"google.sl", "google.do", "google.sg", "google.com.bi", "google.tw",
		"google.mx", "google.com.lv", "google.vn", "google.qa", "google.ph",
		"google.pk", "google.jp", "google.com.gr", "google.com.cn", "google.ng",
		"google.hk", "google.ua", "google.co.hu", "google.it.ao",
		"google.com.pl", "google.com.ru", "google.ne.jp", "google.com.cn",
		"chrome.com", "android.com", "google-analytics.com", "gmail.com",
		"blog.google", "domains.google",
	}
	suspicious := []string{
		"googlea", "googleb", "googlec", "googled", "googlee", "googlef",
		"googleg", "googleh", "googlei", "googlej", "googlek", "googlel",
		"googlem", "googlen", "googleo", "googlep", "googleq", "googler",
		"googles", "googlet", "google", "googlev", "googlew", "googlex",
		"googley", "googlez", "foogle", "eoogle", "coogle", "ooogle", "woogle",
		"gnogle", "gmogle", "gkogle", "ggogle", "gongle", "gomgle", "gokgle",
		"goggle", "goofle", "gooele", "goocle", "gooole", "goowle", "googme",
		"googne", "googhe", "googde", "googld", "googlg", "googla", "googlm",
		"googl", "xn--ggle-qqaa", "xn--oogle-zyf", "xn--ggle-0nda",
		"xn--oogle-72b", "qooqle", "xn--gogle-mkg", "xn--gogle-jsf",
		"xn--googl-lsa", "xn--gogle-jye", "xn--googl-fsa", "xn--oole-ksbc",
		"xn--gogle-7dc", "xn--gogle-vob", "xn--oole-kxac", "xn--ggle-lgba",
		"xn--gogle-kye", "xn--oogle-v1a", "xn--gogle-jua", "xn--goole-tmc",
		"g00gle", "xn--ggle-55da", "xn--gogle-jye", "xn--gogle-f91b",
		"xn--oole-9wac", "xn--goole-b2a", "xn--goole-b3b", "xn--gogle-sce",
		"xn--ggle-v0ba", "gooqle", "xn--ggle-vifa", "xn--googl-f2e",
		"xn--gogle-rce", "xn--gogle-lkg", "xn--gogle-0ta", "xn--gogle-kye",
		"xn--oogle-j1a", "xn--googl-yza", "xn--goole-2yf", "xn--gogle-uob",
		"xn--googl-flf", "xn--gogle-6dc", "xn--ggle-0nda", "xn--googl-3we",
		"g0ogle", "qoogle", "xn--gogle-1ta", "googie", "xn--gogle-281b",
		"xn--googl-rsa", "xn--gogle-381b", "go0gle", "xn--gogle-rce", "goog1e",
		"xn--googe-koc", "xn--oole-47bc", "xn--ggle-5qaa", "xn--oogle-qmc",
		"xn--ggle-qx5aa", "xn--gogle-isf", "xn--oole-zwac", "xn--goole-y1a",
		"xn--googl-r51b", "xn--gogle-kua", "xn--googe-n7a", "xn--gogle-g91b",
		"xn--ggle-55da", "xn--oole-p0ec", "xn--oole-z7bc", "xn--googl-59d",
		"xn--goole-m1a", "xn--goole-zmc", "xn--googl-z0a", "xn--googl-b0a",
		"xn--gogle-sce", "xn--oogle-wmc", "xn--googl-mza", "xn--oogle-71a",
		"xn--oole-9hfc", "xn--oogle-vjg", "xn--ggle-bvea", "xn--ggle-gx5aa",
		"xn--goole-yjg", "xn--googl-n0a", "g-oogle", "go-ogle", "goo-gle",
		"goog-le", "googl-e", "goopgle", "googlke", "googlme", "googzle",
		"go0ogle", "googloe", "gloogle", "gookgle", "goofgle", "goobgle",
		"googvle", "goo9gle", "gokogle", "googtle", "gpoogle", "go9ogle",
		"goolgle", "googyle", "goo0gle", "g9oogle", "gooigle", "gopogle",
		"googmle", "googble", "googlpe", "googfle", "goovgle", "goohgle",
		"goozgle", "googhle", "goiogle", "gologle", "gooygle", "googole",
		"gioogle", "g0oogle", "googkle", "gkoogle", "gootgle", "googple",
		"googl", "goole", "googe", "oogle", "gogle", "googgle", "ggoogle",
		"googlle", "gooogle", "googke", "gpogle", "toogle", "googlw", "gopgle",
		"googlr", "googls", "hoogle", "g9ogle", "goohle", "googlz", "go9gle",
		"zoogle", "goigle", "golgle", "glogle", "gooyle", "googoe", "voogle",
		"googl3", "goozle", "googpe", "gootle", "goovle", "giogle", "googl4",
		"gooble", "yoogle", "boogle", "g.oogle", "go.ogle", "goo.gle",
		"goog.le", "googl.e", "ogogle", "gogole", "goolge", "googel", "gaogle",
		"geogle", "googlo", "googli", "guogle", "gougle", "goegle", "goagle",
		"googlecom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
