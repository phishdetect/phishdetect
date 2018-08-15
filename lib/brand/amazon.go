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

// Amazon brand properties.
func Amazon() *Brand {
	name := "amazon"
	original := []string{"amazon"}
	whitelist := []string{
		"amazon.com", "amazon.fr", "amazon.it", "amazon.de", "amazon.ca",
		"amazon.co.uk", "amazon.in", "amazon.ru", "amazon.nl", "amazon.com.mx",
		"amazon.es", "amazon.com.au", "amazon.com.br", "ssl-images-amazon.com",
		"amazon-adsystem.com", "assoc-amazon.com", "payments-amazon.com",
		"media-amazon.com", "amazon.co.jp",
	}
	suspicious := []string{
		"amazonb", "amazonc", "amazond", "amazone", "amazonf", "amazong",
		"amazonh", "amazoni", "amazonj", "amazonk", "amazonl", "amazonm",
		"amazonn", "amazono", "amazonp", "amazonq", "amazonr", "amazons",
		"amazont", "amazon", "amazonv", "amazonw", "amazonx", "amazony",
		"amazonz", "cmazon", "emazon", "imazon", "qmazon", "alazon", "aoazon",
		"aiazon", "aeazon", "a-azon", "amczon", "amezon", "amizon", "amqzon",
		"amaxon", "amaron", "amajon", "amaznn", "amazmn", "amazkn", "amazgn",
		"amazoo", "amazol", "amazoj", "amazof", "xn--mazon-qwa", "xn--amzon-ucc",
		"xn--mazon-zjc", "xn--mzon-pzbb", "xn--mzon-9nab", "amaz0n",
		"xn--mzon-4nab", "xn--amzon-1jc", "xn--amzon-k11b", "annazon",
		"xn--mazon-i11b", "xn--mzon-koab", "xn--amzon-nra", "arrazon",
		"xn--amaon-x59a", "xn--amazn-i91b", "xn--amzon-sqa", "xn--amazn-uce",
		"xn--mzon-znab", "xn--aazon-6xe", "xn--amaon-vuc", "xn--mzon-poab",
		"xn--amzon-swa", "anazon", "xn--mzon-fseb", "xn--amzon-yqa",
		"xn--aazon-919a", "xn--amzon-4qa", "xn--mzon-4q5ab", "xn--amzon-hra",
		"xn--mzon-foab", "xn--mzon-p5bb", "xn--amazn-xob", "xn--amazn-581b",
		"xn--mazon-3ve", "xn--mazon-jwb", "xn--amaon-kib", "xn--amazn-okg",
		"xn--amazn-mye", "xn--amazn-lsf", "xn--mzon-zsab", "xn--amzon-bra",
		"xn--mzon-zmbb", "amazor", "xn--mazon-1of", "amazom", "xn--mazon-wqa",
		"xn--amazn-3ta", "xn--amazn-uce", "xn--mazon-fra", "arnazon",
		"xn--amazn-mua", "xn--aazon-ipc", "xn--mazon-8qa", "xn--amaon-7hb",
		"xn--aazon-fl1b", "xn--amazn-mye", "xn--mazon-2qa", "xn--mazon-scc",
		"xn--mazon-qqa", "xn--mazon-lra", "xn--amzon-lwb", "xn--amzon-5ve",
		"xn--amazn-9dc", "xn--amazo-07a", "xn--mzon-43db", "xn--amzon-3of",
		"a-mazon", "am-azon", "ama-zon", "amaz-on", "amazo-n", "amsazon",
		"amyazon", "amazqon", "amjazon", "anmazon", "ama3zon", "ajmazon",
		"amayzon", "apmazon", "amazxon", "am1azon", "ama2zon", "amwazon",
		"amazokn", "ama6zon", "amazuon", "amnazon", "amazpon", "amaz6on",
		"amazton", "amaz9on", "am2azon", "amazson", "ampazon", "ama1zon",
		"amlazon", "amawzon", "amaz7on", "amazo9n", "almazon", "amazlon",
		"amaszon", "amatzon", "amazopn", "amahzon", "amazgon", "amaz0on",
		"amazoin", "amazaon", "amaezon", "amkazon", "amqazon", "amaxzon",
		"amauzon", "amazzon", "akmazon", "amazhon", "amazion", "amaazon",
		"amazoln", "amagzon", "amazeon", "amaz3on", "amzazon", "amazo0n",
		"amaqzon", "amaz2on", "ama7zon", "amazkon", "amaon", "mazon", "amzon",
		"aazon", "amazo", "amazn", "aamazon", "amazoon", "ammazon", "amazln",
		"amwzon", "ajazon", "am2zon", "amaton", "amzzon", "ama3on", "amaaon",
		"ama2on", "ama7on", "amahon", "ymazon", "amagon", "wmazon", "amazin",
		"amaeon", "apazon", "amazpn", "am1zon", "amaz9n", "amazoh", "ama6on",
		"amyzon", "amszon", "amazob", "1mazon", "amason", "amauon", "smazon",
		"zmazon", "amaqon", "2mazon", "akazon", "a.mazon", "am.azon", "ama.zon",
		"amaz.on", "amazo.n", "maazon", "aamzon", "amzaon", "amaozn", "amazno",
		"omazon", "amuzon", "amazan", "amazen", "amozon", "amazun", "umazon",
		"amazoncom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
