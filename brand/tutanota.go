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

// Tutanota brand properties.
func Tutanota() *Brand {
	name := "tutanota"
	original := []string{"tutanota"}
	whitelist := []string{"tutanota.com", "tutanota.de", "tuta.io", "tutao.de"}
	suspicious := []string{
		"uutanota", "vutanota", "putanota", "dutanota", "4utanota", "tttanota", "twtanota", "tqtanota", "tetanota", "t5tanota", "tuuanota", "tuvanota", "tupanota", "tudanota", "tu4anota", "tutcnota", "tutenota", "tutinota", "tutqnota", "tutaoota", "tutalota", "tutajota", "tutafota", "tutannta", "tutanmta", "tutankta", "tutangta", "tutanoua", "tutanova", "tutanopa", "tutanoda", "tutano4a", "tutanotc", "tutanote", "tutanoti", "tutanotq", "tu6tanota", "tutankota", "tutzanota", "tutan9ota", "tutabnota", "tutaqnota", "tiutanota", "tugtanota", "tutanorta", "tutanogta", "tutanhota", "tutano0ta", "tutaniota", "tutanotza", "tutanjota", "tutanozta", "tutanotra", "tuztanota", "tutanoita", "tut1anota", "tutano6ta", "tutanmota", "tutanbota", "tut2anota", "tutahnota", "tuytanota", "t7utanota", "tujtanota", "tutawnota", "tuta2nota", "tutanpota", "tu7tanota", "turtanota", "tutajnota", "tutyanota", "tuitanota", "tutamnota", "tutanoyta", "tuhtanota", "tuta1nota", "tut6anota", "tutganota", "tjutanota", "tutanotya", "t8utanota", "tu5tanota", "tuftanota", "tutasnota", "tutano5ta", "tutsanota", "tutan0ota", "tutanotfa", "tutwanota", "thutanota", "tutanotga", "tutanot6a", "tut5anota", "tutanofta", "tutqanota", "tutanokta", "tutaynota", "tutranota", "tutaznota", "tutanot5a", "tutanolta", "tutanlota", "tutano9ta", "tu8tanota", "tutfanota", "tyutanota", "tzutanota", "tutanopta", "tutanot", "tuanota", "tutnota", "tutanoa", "utanota", "tutanta", "tutaota", "ttanota", "ttutanota", "tuttanota", "tutanoota", "tutanotta", "tuutanota", "tutannota", "tutaanota", "tuyanota", "tutanoty", "rutanota", "tu6anota", "tutanotz", "tytanota", "tutanora", "5utanota", "tutanots", "tutanlta", "tutanoza", "tutznota", "tutynota", "tufanota", "tztanota", "tuzanota", "tutano5a", "tutwnota", "t8tanota", "tut2nota", "tutsnota", "tutanoga", "futanota", "tutanotw", "zutanota", "turanota", "tutano6a", "6utanota", "tut1nota", "t7tanota", "tutanot2", "tutanpta", "tutahota", "tutanoya", "titanota", "tutanita", "yutanota", "tutabota", "gutanota", "tjtanota", "tuganota", "tutan9ta", "tutanot1", "thtanota", "tutanofa", "tu5anota", "uttanota", "ttuanota", "tuatnota", "tutnaota", "tutaonta", "tutantoa", "tutanoat", "tutunota", "tutaneta", "totanota", "tutanot", "tutanoto", "tatanota", "tutanata", "tutanuta", "tutonota", "tutanotacom", "xn--tutnot-duad", "xn--uanoa-6dbbd", "xn--tutnot-dxcd", "xn--tutanta-dpf", "xn--ttanota-6li", "xn--tutnota-7wa", "xn--tutnota-4fg", "xn--tutnot-5nfd", "xn--tutnota-nbd", "xn--ttanota-mqf", "xn--tutanta-e1a", "xn--tutnot-rtad", "xn--tutnot-rlgd", "xn--tutnot-ktad", "xn--tutnota-bwa", "tutan0ta", "xn--ttanota-htb", "xn--tutnot-yocd", "xn--tutanot-kxa", "xn--tutanot-cxa", "xn--tutnota-jwa", "xn--tutanot-fwa", "xn--tutanot-3wa", "xn--tutanot-vwa", "xn--ttanota-d31c", "xn--tutanot-50c", "xn--tuanota-7qb", "xn--utanota-5jg", "xn--tutanta-x2c", "xn--tutnot-yc8bd", "xn--utanota-dqf", "xn--tutanta-h5b", "xn--tutanot-iih", "xn--uanoa-6yebd", "tutarota", "xn--uanota-orfb", "xn--tutnota-10c", "xn--tutanot-tgc", "xn--tutanta-0mh", "xn--tutanta-ejg", "xn--tutnot-k0ad", "xn--tutnot-ytad", "xn--tutanoa-crb", "xn--tutnota-rwa", "xn--tuanoa-j1ed", "xn--tutanot-rbd", "xn--ttanota-kof", "xn--tutanot-gn4c", "xn--tutanta-gx4c", "xn--tuanota-fqf", "xn--uanoa-ldebd", "xn--utanota-5qb", "xn--tutnota-eih", "xn--tutanot-8fg", "xn--tutnota-gxa", "tutamota", "xn--tutanot-nwa", "xn--tuanoa-qrfd", "xn--tutanta-ejg", "xn--tutanta-4ni", "xn--tutanoa-ckg", "xn--tutnota-cn4c", "xn--tutnot-55bd", "xn--tutnota-b4a", "xn--tuanoa-qkbd", "xn--tutaota-6jb", "xn--ttanota-3kg", "xn--uanota-okbb", "xn--tutnota-pgc", "xn--uanota-h1eb", "xn--tutanoa-jqf", "xn--tutnot-5tad", "xn--tutanta-p0a", "xn--tuanota-7jg", "xn--ttanota-6li", "xn--tutanot-f4a", "xn--tutnot-kuad", "xn--ttanota-0hc", "xn--tutanta-wx4c", "xn--tutanta-dpf", "xn--tutnota-zwa",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
