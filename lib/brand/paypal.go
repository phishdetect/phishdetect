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

// PayPal brand properties.
func PayPal() *Brand {
	name := "paypal"
	original := []string{"paypal"}
	whitelist := []string{
		"paypal.com", "paypal.com", "paypal.com.au", "paypal.at", "paypal.be",
		"paypal.ca", "paypal.fr", "paypal.de", "paypal.com.hk", "paypal.it",
		"paypal.com.mx", "paypal.nl", "paypal.pl", "paypal.com.sg", "paypal.es",
		"paypal.ch", "paypal.co.uk",
	}
	suspicious := []string{
		"qaypal", "raypal", "taypal", "xaypal", "0aypal", "pcypal", "peypal",
		"piypal", "pqypal", "paxpal", "paqpal", "paipal", "pa9pal", "payqal",
		"payral", "paytal", "payxal", "pay0al", "paypcl", "paypel", "paypil",
		"paypql", "paypam", "paypan", "paypah", "paypad", "payypal", "paypayl",
		"pa7ypal", "paxypal", "paypa2l", "payopal", "paypsal", "payapal",
		"paypzal", "pa1ypal", "paygpal", "paypasl", "pagypal", "pahypal",
		"paypoal", "pasypal", "pay0pal", "paytpal", "payplal", "pauypal",
		"paylpal", "paypmal", "p1aypal", "pa2ypal", "payp1al", "patypal",
		"pwaypal", "paympal", "payspal", "paypwal", "pay7pal", "payhpal",
		"pawypal", "payp2al", "paypyal", "pa6ypal", "paqypal", "paypa1l",
		"p2aypal", "payupal", "pay6pal", "pazypal", "psaypal", "payp0al",
		"paypazl", "paaypal", "pyaypal", "pzaypal", "paypawl", "pqaypal",
		"paypqal", "paypaql", "payxpal", "paypl", "pypal", "paypa", "papal",
		"payal", "aypal", "payppal", "paypaal", "ppaypal", "pzypal",
		"psypal", "pahpal", "laypal", "p2ypal", "paypzl", "maypal", "pa6pal",
		"paupal", "patpal", "paypsl", "paymal", "paylal", "p1ypal", "pwypal",
		"pagpal", "payp1l", "paypao", "paypak", "payp2l", "paapal", "paypap",
		"paspal", "payoal", "pyypal", "paypwl", "paypyl", "pa7pal", "oaypal",
		"apypal", "pyapal", "papyal", "payapl", "paypla", "paypol", "puypal",
		"poypal", "paypul", "paypalcom", "paypai", "pavypal", "xn--paypl-jra",
		"xn--pypl-qoac", "xn--paypl-m11b", "xn--papal-rva", "xn--pypal-j11b",
		"xn--paypl-wcc", "xn--pypl-0sac", "xn--pypal-kwb", "paypa1",
		"xn--pypl-5nac", "xn--aypal-2ce", "xn--papal-q9d", "xn--paypa-loc",
		"xn--pypal-gra", "xn--pypal-mra", "xn--paypl-3jc", "xn--paypl-7ve",
		"xn--pypl-0mbc", "xn--payal-yva", "xn--pypl-53dc", "xn--ayal-ukbc",
		"xn--paypl-6qa", "xn--pypl-gsec", "xn--paypl-uqa", "xn--ayal-9ndc",
		"xn--papal-xif", "xn--ayal-4vdc", "xn--payal-xye", "xn--payal-5ce",
		"xn--paypl-5of", "xn--paypl-0qa", "xn--payal-lme", "xn--paypl-nwb",
		"xn--paypl-pra", "xn--papal-fze", "xn--pypal-xqa", "xn--payal-1tb",
		"xn--pypal-tcc", "xn--papal-ouc", "xn--paypl-uwa", "xn--pypl-goac",
		"xn--pypl-boac", "xn--pypal-9qa", "xn--pypal-4ve", "xn--pypal-0jc",
		"xn--aypal-vva", "xn--paypa-o7a", "xn--aypal-ytb", "xn--pypal-3qa",
		"xn--pypal-2of", "xn--pypal-rqa", "xn--pypl-qzbc", "xn--pypl-5q5ac",
		"xn--aypal-ime", "xn--ayal-f6dc", "xn--paypl-dra", "xn--ayal-9rac",
		"xn--pypl-0nac", "xn--pypal-rwa", "xn--pypl-q5bc", "xn--aypal-uye",
		"xn--pypl-loac",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
