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

// Yahoo brand properties.
func Yahoo() *Brand {
	name := "yahoo"
	original := []string{"yahoo"}
	whitelist := []string{
		"yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk", "yahoo.fr", "yahoo.com.br", "yahoo.co.in", "yahoo.ca", "yahoo.com.ar", "yahoo.com.cn", "yahoo.com.mx", "yahoo.co.kr", "yahoo.co.nz", "yahoo.com.hk", "yahoo.com.sg", "yahoo.es", "yahoo.gr", "yahoo.de", "yahoo.com.ph", "yahoo.com.tw", "yahoo.dk", "yahoo.ie", "yahoo.it", "yahoo.se", "yahoo.com.au", "yahoo.co.id", "yahoo.cl", "yahoo.co.jp", "yahoo.co.th", "yahoo.com.co", "yahoo.com.my", "yahoo.com.tr", "yahoo.com.ve", "yahoo.com.vn", "yahoo.in", "yahoo.nl", "yahoo.no", "yahoo.pl", "yahoo.ro", "yahoo.net",
	}
	suspicious := []string{
		"yahooa", "yahoob", "yahooc", "yahood", "yahooe", "yahoof", "yahoog", "yahooh", "yahooi", "yahooj", "yahook", "yahool", "yahoom", "yahoon", "yahooo", "yahoop", "yahooq", "yahoor", "yahoos", "yahoot", "yahoo", "yahoov", "yahoow", "yahoox", "yahooy", "yahooz", "xahoo", "qahoo", "iahoo", "9ahoo", "ychoo", "yehoo", "yihoo", "yqhoo", "yaioo", "yajoo", "yaloo", "yaxoo", "yahno", "yahmo", "yahko", "yahgo", "yahon", "yahom", "yahok", "yahog", "xn--yaho-ogb", "xn--yaoo-wff", "xn--yhoo-boa", "xn--yhoo-qzb", "xn--yhoo-5q5a", "xn--yaho-tx5a", "xn--yhoo-qoa", "yaho0", "yah00", "yalhoo", "xn--yaho-sqa", "xn--yah-inaa", "xn--yaoo-me", "xn--yaho-85d", "xn--yaho-2nd", "xn--yah-vlza", "xn--yaho-ngb", "xn--yaho-y0b", "xn--yhoo-53d", "xn--ahoo-9ld", "xn--yaho-7qa", "xn--yah-czca", "xn--yah-moba", "xn--yaho-3nd", "xn--yhoo-0na", "xn--yhoo-0sa", "xn--yaho-x0b", "xn--yaho-3nd", "xn--yaho-75d", "xn--yah-3lza", "xn--ahoo-kfc", "xn--yhoo-0mb", "xn--yaho-eve", "xn--yah-unaa", "xn--yhoo-loa", "xn--yaho-yif", "xn--yhoo-5na", "xn--yaho-xif", "xn--yaho-tqa", "xn--yah-5xda", "xn--yaho-8qa", "xn--ahoo-9me", "xn--yhoo-goa", "xn--ahoo-4ra", "xn--yah-ueda", "yah0o", "xn--yhoo-q5b", "xn--yaho-75d", "xn--yah-czca", "xn--yaho-dve", "xn--yhoo-gse", "xn--yaho-85d", "xn--yaoo-1oe", "xn--yaho-ix5a", "xn--yaho-sx5a", "xn--yaho-jx5a", "yaihoo", "xn--yah-7gea", "xn--yah-e7aa", "xn--ahoo-u6d", "xn--yaoo-15d", "xn--yah-ueda", "xn--yaho-2nd", "y-ahoo", "ya-hoo", "yah-oo", "yaho-o", "yazhoo", "yahioo", "yahnoo", "yahjoo", "yahoko", "yashoo", "yahoio", "yauhoo", "yahuoo", "yaghoo", "yahzoo", "yah0oo", "yahboo", "yahloo", "y1ahoo", "ysahoo", "yahopo", "yajhoo", "yaho9o", "yahkoo", "yzahoo", "ywahoo", "yanhoo", "yayhoo", "ya1hoo", "yaholo", "yahgoo", "yyahoo", "yahyoo", "yabhoo", "yahpoo", "ya2hoo", "yqahoo", "yawhoo", "yaho0o", "y2ahoo", "yah9oo", "yaqhoo", "yaoo", "ahoo", "yaho", "yhoo", "yahhoo", "yaahoo", "yahlo", "yah9o", "gahoo", "yaho9", "yahpo", "uahoo", "yazoo", "yyhoo", "hahoo", "yaboo", "tahoo", "yahoi", "aahoo", "yshoo", "yahio", "6ahoo", "yzhoo", "yahop", "yahol", "yanoo", "yauoo", "7ahoo", "yayoo", "yagoo", "sahoo", "y2hoo", "ywhoo", "y1hoo", "y.ahoo", "ya.hoo", "yah.oo", "yaho.o", "ayhoo", "yhaoo", "yaoho", "yuhoo", "yohoo", "yahoe", "yahoa", "yahuo", "yahao", "yaho", "yaheo", "yahoocom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
