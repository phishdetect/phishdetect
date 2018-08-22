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

// Instagram brand properties.
func Instagram() *Brand {
	name := "instagram"
	original := []string{"instagram"}
	whitelist := []string{"instagram.com"}
	suspicious := []string{
		"instagramb", "instagramc", "instagramd", "instagrame", "instagramf",
		"instagramg", "instagramh", "instagramj", "instagramk", "instagraml",
		"instagramm", "instagramn", "instagramo", "instagramp", "instagramq",
		"instagramr", "instagrams", "instagramt", "instagramu", "instagramv",
		"instagramw", "instagramx", "instagramy", "instagramz", "hnstagram",
		"knstagram", "mnstagram", "anstagram", "ynstagram", "iostagram",
		"ilstagram", "ijstagram", "ifstagram", "inrtagram", "inqtagram",
		"inwtagram", "inctagram", "in3tagram", "insuagram", "insvagram",
		"inspagram", "insdagram", "ins4agram", "instcgram", "instegram",
		"instigram", "instqgram", "instafram", "instaeram", "instacram",
		"instaoram", "instawram", "instagsam", "instagpam", "instagvam",
		"instagzam", "instagbam", "instag2am", "instagrcm", "instagrem",
		"instagrim", "instagrqm", "instagral", "instagrao", "instagrai",
		"instagrae", "xn--instaram-zti", "xn--nstagram-j99a",
		"xn--instaram-dtd", "xn--instaram-toj", "xn--instagra-cbh",
		"xn--nstagram-0ud", "xn--instagrm-tx0d", "instagrarr",
		"xn--intagram-7n0b", "xn--instagrm-g0a", "xn--nstagram-t2a",
		"xn--instagam-c0d", "xn--instgram-9pc", "xn--instagrm-4ei",
		"xn--instaram-chb", "instaqram", "xn--instagrm-1od", "xn--instagra-bxd",
		"irstagram", "xn--intagram-lhh", "xn--insagram-qxb", "instagrarn",
		"xn--instgrm-cwac", "xn--instgram-cza", "xn--instgrm-20cc",
		"xn--instaram-3sd", "instagran", "xn--instgrm-c4ac",
		"xn--instagam-c57c", "xn--instagra-o89c", "xn--instagrm-fza",
		"xn--insagram-qch", "lnstagram", "xn--instagrm-dqc", "xn--instgram-5dd",
		"xn--nstagram-fcg", "xn--istagram-ppb", "xn--instgram-46g",
		"xn--nstagram-rjb", "xn--instagrm-57a", "xn--instgram-3za", "1nstagram",
		"xn--instgram-yod", "xn--instagam-y7g", "xn--instgram-lza",
		"xn--instagrm-8dd", "xn--instgram-qx0d", "xn--instagam-2zd",
		"xn--instgram-d0a", "xn--instgrm-hxac", "xn--instgrm-5fgc",
		"xn--instgrm-dn4cc", "xn--instagrm-6za", "xn--instgram-27a",
		"xn--intagram-557f", "xn--nstagram-oqc", "xn--insagram-cfg",
		"xn--instgrm-8wac", "xn--instgrm-fihc", "xn--instgrm-kwac",
		"xn--instagam-30d", "xn--intagram-nvb", "xn--instgram-1ei",
		"xn--intagram-i1d", "xn--instgram-uza", "xn--instagra-yy7c",
		"xn--instaram-c0c", "xn--instgram-2ya", "xn--instagrm-oza",
		"xn--instagrm-76g", "xn--instgrm-qgcc", "xn--instaram-bgb",
		"xn--instgrm-obdc", "xn--nstagram-skb", "xn--nstagram-5152a",
		"xn--instgrm-swac", "xn--instgrm-0wac", "xn--instaram-tgb",
		"xn--nstagram-b2a", "xn--instagrm-5ya", "xn--instagrm-xza", "imstagram",
		"instagrann", "i-nstagram", "in-stagram", "ins-tagram", "inst-agram",
		"insta-gram", "instag-ram", "instagr-am", "instagra-m", "imnstagram",
		"insatagram", "insztagram", "insgtagram", "injstagram", "inqstagram",
		"instagvram", "instagfram", "instagraqm", "inst6agram", "instawgram",
		"insta1gram", "insdtagram", "instagream", "inswtagram", "ibnstagram",
		"instagra1m", "instzagram", "instaygram", "instgagram", "instagr2am",
		"inbstagram", "instagrwam", "instragram", "instagrtam", "inestagram",
		"instagzram", "instabgram", "inst1agram", "inhstagram", "inmstagram",
		"instagbram", "instagryam", "instfagram", "ijnstagram", "inzstagram",
		"instagrqam", "instagrzam", "instag4ram", "insqtagram", "insrtagram",
		"instagdram", "instazgram", "instageram", "instatgram", "inst2agram",
		"insytagram", "instagraym", "instaghram", "insta2gram", "instafgram",
		"instagr1am", "inxstagram", "inwstagram", "insetagram", "insftagram",
		"instaqgram", "instsagram", "instahgram", "insxtagram", "inastagram",
		"instagrsam", "instavgram", "ihnstagram", "inst5agram", "instwagram",
		"ins5tagram", "ins6tagram", "instagyram", "instagrasm", "instagrfam",
		"instag5ram", "inystagram", "indstagram", "instqagram", "instagr5am",
		"instagra2m", "instagrawm", "instagrazm", "instyagram", "instagr4am",
		"instagrdam", "instagtram", "instasgram", "instaram", "nstagram",
		"instgram", "instagrm", "insagram", "instagam", "instagra", "istagram",
		"intagram", "insstagram", "insttagram", "instaagram", "instagraam",
		"innstagram", "instagrram", "iinstagram", "instaggram", "instagrym",
		"instabram", "instagrak", "inetagram", "instagraj", "instagtam",
		"instagrap", "inxtagram", "instwgram", "instatram", "instzgram",
		"instageam", "insragram", "instahram", "instavram", "8nstagram",
		"inytagram", "unstagram", "ins6agram", "9nstagram", "instayram",
		"instagdam", "instygram", "instsgram", "ins5agram", "onstagram",
		"jnstagram", "inatagram", "instagr1m", "instag5am", "inszagram",
		"instag4am", "instagrzm", "inst1gram", "insgagram", "insfagram",
		"insyagram", "inztagram", "ibstagram", "instazram", "instagr2m",
		"inst2gram", "instagrsm", "instagrwm", "instagfam", "ihstagram",
		"indtagram", "i.nstagram", "in.stagram", "ins.tagram", "inst.agram",
		"insta.gram", "instag.ram", "instagr.am", "instagra.m", "nistagram",
		"isntagram", "intsagram", "insatgram", "instgaram", "instargam",
		"instagarm", "instagrma", "enstagram", "instagrom", "instagrum",
		"instugram", "instogram", "instagra",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
