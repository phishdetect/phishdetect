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

// ProtonMail brand properties.
func ProtonMail() *Brand {
	name := "protonmail"
	original := []string{"protonmail"}
	whitelist := []string{"protonmail.com", "protonmail.ch"}
	suspicious := []string{
		"protonmaila", "protonmailb", "protonmailc", "protonmaild",
		"protonmaile", "protonmailf", "protonmailg", "protonmailh",
		"protonmaili", "protonmailj", "protonmailk", "protonmaill",
		"protonmailm", "protonmailn", "protonmailo", "protonmailp",
		"protonmailq", "protonmailr", "protonmails", "protonmailt",
		"protonmail", "protonmailv", "protonmailw", "protonmailx",
		"protonmaily", "protonmailz", "qrotonmail", "rrotonmail", "trotonmail",
		"xrotonmail", "0rotonmail", "psotonmail", "ppotonmail", "pvotonmail",
		"pzotonmail", "pbotonmail", "p2otonmail", "prntonmail", "prmtonmail",
		"prktonmail", "prgtonmail", "prouonmail", "provonmail", "proponmail",
		"prodonmail", "pro4onmail", "protnnmail", "protmnmail", "protknmail",
		"protgnmail", "protoomail", "protolmail", "protojmail", "protofmail",
		"protonlail", "protonoail", "protoniail", "protoneail", "proton-ail",
		"protonmcil", "protonmeil", "protonmiil", "protonmqil", "protonmahl",
		"protonmakl", "protonmaml", "protonmaal", "protonmayl", "protonmaim",
		"protonmain", "protonmaih", "protonmaid", "xn--protonmal-i0c",
		"xn--protnmail-ol7d", "xn--rotonmail-91g", "xn--protonmil-c2d",
		"xn--protonmal-s93b", "xn--proonmail-73h", "xn--prtnmail-necb",
		"protommail", "protonnnail", "xn--protnmail-32h", "xn--protonmil-cqd",
		"xn--prtnmail-obhb", "xn--protonmil-12a", "xn--prtonmail-17a",
		"xn--prtonmail-6l7d", "xn--protnmail-8l7d", "xn--protonmil-rbj",
		"xn--protonmil-6yh", "xn--potonmail-lge", "xn--protonmal-xp06a",
		"xn--potonmail-vzh", "xn--protonmal-xob", "protonmall",
		"xn--prtonmail-12h", "xn--potonmail-gfe", "xn--protonmai-yub",
		"xn--potonmail-qfe", "xn--protonail-qx3d", "xn--protnmail-32h",
		"xn--protnmail-ymc", "protonma1l", "xn--protonail-l2h",
		"xn--proonmail-72g", "xn--rotonmail-fvc", "xn--potonmail-q43d",
		"xn--protonmil-676d", "xn--prtonmail-hrk", "xn--protonmal-n5a",
		"xn--protonmil-wzc", "xn--prtonmail-ml7d", "xn--prtnmail-z80db",
		"xn--protonmil-r2a", "protonnail", "xn--prtnmail-w3ab",
		"xn--rotonmail-k3h", "xn--protonmil-wcb", "xn--protomail-fvb",
		"xn--protonmil-61a", "xn--prtonmail-66a", "xn--protnmail-t1g",
		"xn--protonmil-c3a", "xn--protnmail-jsd", "xn--prtnmail-0dgb",
		"pr0tonmail", "xn--protnmail-ehj", "xn--prtonmail-12h",
		"xn--rotonmail-zih", "prot0nmail", "xn--prtnmail-i90db",
		"xn--prtonmail-wmc", "xn--prtnmail-obhb", "xn--protonmal-7zg",
		"xn--rotonmail-99a", "xn--prtnmail-0dgb", "xn--protonmil-h2a",
		"xn--proonmail-73b", "xn--prtonmail-r1g", "protormail", "protonrrail",
		"xn--protonmai-t9d", "xn--protonmal-75a", "xn--protonmil-w1a",
		"xn--prtonmail-r1g", "protonmaii", "xn--protonmal-78d",
		"xn--prtonmail-chj", "pr0t0nmail", "xn--protnmail-86a",
		"xn--prtonmail-hsd", "protonmai1", "xn--protonmal-2pb",
		"xn--protnmail-37a", "xn--prtnmail-o4ab", "xn--protonail-bh6d",
		"xn--protnmail-t1g", "xn--protonail-gce", "xn--prtnmail-5fdb",
		"xn--prtnmail-rpjb", "xn--protnmail-jrk", "protonrnail",
		"xn--prtnmail-4jib", "p-rotonmail", "pr-otonmail", "pro-tonmail",
		"prot-onmail", "proto-nmail", "proton-mail", "protonm-ail",
		"protonma-il", "protonmai-l", "pfrotonmail", "protonbmail",
		"protonmyail", "prkotonmail", "protonmazil", "protonmqail",
		"prot9onmail", "protonmaiol", "protzonmail", "protonma8il",
		"protonmajil", "pr0otonmail", "perotonmail", "protonma1il",
		"proftonmail", "proitonmail", "p5rotonmail", "prlotonmail",
		"protobnmail", "protponmail", "protonmasil", "proytonmail",
		"proto9nmail", "protonmayil", "protonmaiul", "protonmnail",
		"pro0tonmail", "protohnmail", "protonma9il", "prot0onmail",
		"pro6tonmail", "protonmaijl", "pdrotonmail", "protonmkail",
		"prot5onmail", "pr5otonmail", "protfonmail", "protonmawil",
		"prot6onmail", "protojnmail", "protgonmail", "protonmzail",
		"pro5tonmail", "prpotonmail", "protonmaqil", "protonmwail",
		"proto0nmail", "protonmjail", "protonmpail", "protlonmail",
		"protonhmail", "protonmai9l", "pr4otonmail", "protonma2il",
		"protonmsail", "protonkmail", "prortonmail", "protonnmail",
		"protonmmail", "ptrotonmail", "protonmaikl", "priotonmail",
		"proltonmail", "proptonmail", "protronmail", "protonmauil",
		"p4rotonmail", "proktonmail", "prfotonmail", "protonmlail",
		"protonmaoil", "protolnmail", "protonmakil", "protonjmail",
		"pro9tonmail", "pr9otonmail", "proztonmail", "protoknmail",
		"protoinmail", "protionmail", "protopnmail", "preotonmail",
		"protonlmail", "protonm1ail", "protyonmail", "protonmai8l",
		"progtonmail", "prtotonmail", "prdotonmail", "protonm2ail",
		"protkonmail", "protomnmail", "protonpmail", "protonail", "protonmil",
		"rotonmail", "proonmail", "protnmail", "prtonmail", "potonmail",
		"protonmai", "protomail", "protonmal", "prrotonmail", "protoonmail",
		"pprotonmail", "protonmaail", "prootonmail", "protonmaiil",
		"prottonmail", "protonpail", "proyonmail", "protonmaip", "protonmajl",
		"prptonmail", "protonm2il", "protonmaul", "protonm1il", "peotonmail",
		"protonkail", "pfotonmail", "protpnmail", "protonmaik", "protonmaol",
		"protonmaio", "pro5onmail", "p5otonmail", "pdotonmail", "prozonmail",
		"ptotonmail", "prltonmail", "protonmsil", "p4otonmail", "protonmyil",
		"protohmail", "pritonmail", "protonma8l", "protonjail", "pro6onmail",
		"pr9tonmail", "proronmail", "mrotonmail", "protonmwil", "protlnmail",
		"orotonmail", "progonmail", "protobmail", "prot9nmail", "protonma9l",
		"profonmail", "lrotonmail", "protonmzil", "protinmail", "p.rotonmail",
		"pr.otonmail", "pro.tonmail", "prot.onmail", "proto.nmail",
		"proton.mail", "protonm.ail", "protonma.il", "protonmai.l",
		"rpotonmail", "portonmail", "prtoonmail", "prootnmail", "protnomail",
		"protomnail", "protonamil", "protonmial", "protonmali", "prutonmail",
		"protonmuil", "protanmail", "protenmail", "protonmoil", "protunmail",
		"pretonmail", "pratonmail", "protonmael", "protonmailcom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
