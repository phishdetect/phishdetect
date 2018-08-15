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

// Facebook brand properties.
func Facebook() *Brand {
	name := "facebook"
	original := []string{"facebook"}
	whitelist := []string{"facebook.com", "fbcdn.net", "fb.me", "fbsbx.com"}
	suspicious := []string{
		"facebooka", "facebookb", "facebookc", "facebookd", "facebooke",
		"facebookf", "facebookg", "facebookh", "facebooki", "facebookj",
		"facebookk", "facebookl", "facebookm", "facebookn", "facebooko",
		"facebookp", "facebookq", "facebookr", "facebooks", "facebookt",
		"facebook", "facebookv", "facebookw", "facebookx", "facebooky",
		"facebookz", "fccebook", "fecebook", "ficebook", "fqcebook", "fabebook",
		"faaebook", "fagebook", "fakebook", "fasebook", "facdbook", "facgbook",
		"facabook", "facmbook", "facubook", "facecook", "facefook", "facejook",
		"facerook", "facebnok", "facebmok", "facebkok", "facebgok", "facebonk",
		"facebomk", "facebokk", "facebogk", "facebooj", "facebooi", "facebooo",
		"facebooc", "facesbook", "faceb0ook", "facebvook", "facvebook",
		"f1acebook", "facrebook", "favcebook", "facebolok", "facdebook",
		"fascebook", "facevbook", "faceblook", "faxcebook", "fafcebook",
		"facedbook", "fawcebook", "facebokok", "faqcebook", "facegbook",
		"fac4ebook", "faceboo0k", "facebo0ok", "fadcebook", "facwebook",
		"face3book", "fac3ebook", "facebgook", "facewbook", "fazcebook",
		"f2acebook", "faceboo9k", "faceboopk", "fwacebook", "faceboiok",
		"fqacebook", "face4book", "facebpook", "facebkook", "facfebook",
		"facsebook", "facebnook", "facebhook", "facezbook", "facebopok",
		"facebo9ok", "fyacebook", "facehbook", "facebiook", "fa2cebook",
		"facerbook", "facxebook", "fa1cebook", "faceb9ook", "fsacebook",
		"facenbook", "faczebook", "faycebook", "fzacebook", "faceook",
		"facbook", "acebook", "fcebook", "faebook", "faceboo", "facebok",
		"faacebook", "faceboook", "faceebook", "facebbook", "faccebook",
		"ffacebook", "faceblok", "faczbook", "facebolk", "f1cebook", "tacebook",
		"facrbook", "racebook", "fwcebook", "fscebook", "favebook", "f2cebook",
		"fycebook", "facevook", "fzcebook", "faxebook", "facwbook", "fac3book",
		"fadebook", "facebopk", "fac4book", "facegook", "facebo9k", "facebpok",
		"faceboik", "facebool", "fafebook", "facehook", "faceboom", "facebiok",
		"cacebook", "faceb9ok", "facenook", "facsbook", "afcebook", "fcaebook",
		"faecbook", "facbeook", "faceobok", "faceboko", "facibook", "facobook",
		"faceboek", "facebaok", "facebeok", "fucebook", "facebuok", "facebouk",
		"focebook", "faceboak", "facebookcom", "faceb0ok", "facedook",
		"facebooik", "faceb00k", "facebo0k", "faceboolk", "faceboolc",
		"facelbook", "faceibook", "xn--facbook-lya", "xn--facbook-f8a",
		"xn--faebook-ozb", "xn--facebok-h5b", "xn--acebook-2vf",
		"xn--facebk-m0ea", "xn--fcebook-83a", "xn--facebook-43e",
		"xn--fcebook-2fg", "xn--facebok-4ni", "xn--facebok-xx4c",
		"xn--facebok-i5b", "xn--facbook-s9a", "xn--fcebook-cih",
		"xn--facebk-7wba", "xn--faceook-4bd", "xn--facbook-dya",
		"xn--facebk-0xaa", "xn--fcebook-lbd", "xn--facebok-0mh",
		"xn--faceook-egg", "xn--facebok-y2c", "xn--fcebook-exa",
		"xn--facebk-fmha", "xn--facebk-tl8ba", "xn--faebook-zjg",
		"xn--fcebook-9m4c", "xn--facbook-y7a", "xn--facebok-epf",
		"xn--fcebook-8va", "xn--faceboo-wy7e", "xn--fcebook-pwa",
		"xn--facebok-hx4c", "xn--acebook-o2g", "xn--facebok-fjg",
		"xn--facebk-0qfa", "xn--facbook-ts4c", "xn--faebook-6pf",
		"xn--facebok-dpf", "xn--faebook-35a", "xn--acebook-w1b",
		"xn--fcebook-hwa", "xn--facebok-1mh", "xn--facebk-fxaa",
		"xn--facebok-q0a", "xn--facebok-dpf", "xn--facebk-0qfa",
		"xn--facebk-7l8ba", "xn--facebok-ejg", "xn--fcebook-ngc",
		"xn--facbook-9gg", "xn--faebook-64a", "xn--facebok-gx4c",
		"xn--facebok-e1a", "xn--facbook-ddh", "xn--facebok-ejg",
		"xn--facbook-c9a", "xn--facbook-tya", "xn--facebk-m0ea",
		"xn--faceook-kmg", "xn--facebok-fjg", "xn--facbook-dog",
		"xn--facebok-5ni", "xn--facebok-x2c", "xn--faceboo-9nf",
		"xn--facebok-epf", "xn--faebook-vxa", "xn--fcebook-z0c",
		"xn--fcebook-xwa", "xn--facebok-p0a", "xn--facebk-tpga",
		"xn--facebk-mqca", "xn--fcebook-5wa", "xn--facbook-v8a",
		"xn--facebok-f1a", "xn--facbook-0mf", "xn--faceook-4rd",
		"xn--facebok-wx4c",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
