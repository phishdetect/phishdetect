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

// Telegram brand properties.
func Telegram() *Brand {
	name := "telegram"
	original := []string{"telegram"}
	whitelist := []string{"telegram.com", "telegram.org"}
	suspicious := []string{
		"uelegram", "velegram", "pelegram", "delegram", "4elegram", "tdlegram", "tglegram", "talegram", "tmlegram", "tulegram", "temegram", "tenegram", "tehegram", "tedegram", "teldgram", "telggram", "telagram", "telmgram", "telugram", "telefram", "teleeram", "telecram", "teleoram", "telewram", "telegsam", "telegpam", "telegvam", "telegzam", "telegbam", "teleg2am", "telegrcm", "telegrem", "telegrim", "telegrqm", "telegral", "telegrao", "telegrai", "telegrae", "te1egram", "telegrann", "telegrarn", "telegra2m", "teplegram", "tel4egram", "telmegram", "telegeram", "teleg4ram", "telegrsam", "tezlegram", "telegr1am", "telegfram", "telegrazm", "teolegram", "telegraym", "teledgram", "teleygram", "telegrwam", "telesgram", "telzegram", "telegra1m", "telebgram", "telewgram", "telegvram", "telefgram", "teloegram", "telregram", "tele4gram", "tselegram", "telegrzam", "telergram", "tel3egram", "teklegram", "televgram", "telegr5am", "telegraqm", "twelegram", "temlegram", "t4elegram", "teslegram", "telwegram", "tewlegram", "telegtram", "tdelegram", "telegrdam", "teleg5ram", "telegrqam", "trelegram", "telegbram", "telpegram", "telegr4am", "telegyram", "telegryam", "tele3gram", "telegzram", "telehgram", "teldegram", "te4legram", "terlegram", "telegrfam", "telegream", "teletgram", "t3elegram", "tzelegram", "telegdram", "telegr2am", "telegrtam", "telsegram", "telegrawm", "tedlegram", "telegrasm", "telezgram", "telkegram", "te3legram", "teleghram", "telegra", "telegam", "tlegram", "telgram", "telegrm", "teegram", "elegram", "teleram", "telegraam", "teelegram", "telegrram", "teleegram", "teleggram", "ttelegram", "tellegram", "teleg4am", "telebram", "teleg5am", "telegrwm", "telegraj", "telegrak", "telegtam", "telegrap", "tslegram", "telegrzm", "teoegram", "tepegram", "telegeam", "telehram", "telezram", "relegram", "felegram", "trlegram", "telwgram", "tel3gram", "tekegram", "telegr1m", "6elegram", "telegr2m", "telegdam", "televram", "telegrsm", "teleyram", "telegrym", "yelegram", "zelegram", "teletram", "t3legram", "tzlegram", "telegfam", "5elegram", "telrgram", "gelegram", "telzgram", "t4legram", "twlegram", "tel4gram", "telsgram", "etlegram", "tleegram", "teelgram", "telgeram", "telergam", "telegarm", "telegrma", "telogram", "tilegram", "tolegram", "telegrum", "telegrom", "teligram", "telegramcom", "teiegram", "telegran", "telegrarr", "teleqram", "xn--tlgram-iyeb", "xn--tlegram-bdh", "xn--teleram-kfd", "xn--teleram-6mi", "xn--telegrm-sgc", "xn--teleram-ncb", "xn--tlgram-w4ab", "xn--teleram-npc", "xn--telegrm-mwa", "xn--telgram-y7a", "xn--tlegram-bog", "xn--telgram-9gg", "xn--tlegram-rya", "xn--telgram-0mf", "xn--teleram-qbb", "xn--tlegram-t8a", "xn--telgram-dog", "xn--tlegram-98a", "xn--tlgram-33ab", "xn--elegram-dqf", "xn--telegrm-2wa", "xn--tlegram-ymf", "xn--tlgram-bvfb", "xn--telegam-jld", "xn--teleram-ovh", "xn--telegam-r51c", "xn--telegrm-jxa", "xn--teleram-6bb", "xn--telegam-gmd", "xn--telgram-dya", "xn--telegrm-hih", "xn--tlgram-ph8bb", "xn--tlgram-i4ab", "xn--teegram-ojb", "xn--tlegram-rs4c", "xn--tlegram-w7a", "xn--teegram-khd", "xn--tlegram-d8a", "xn--telegrm-ewa", "xn--tlegram-q9a", "xn--telgram-s9a", "xn--telegrm-bxa", "xn--tlgram-b5ab", "xn--tlegram-jya", "xn--telegrm-e4a", "xn--elegram-5qb", "xn--telgram-c9a", "xn--telegrm-qbd", "xn--telgram-f8a", "xn--telegra-zig", "xn--tlegram-7gg", "xn--telgram-lya", "xn--telgram-tya", "xn--telegrm-uwa", "xn--tlegram-bya", "xn--telegam-rld", "xn--telgram-ddh", "xn--tlgram-pvab", "xn--teleram-cfd", "xn--telegrm-40c", "xn--tlgram-3ofb", "xn--telegra-3z1c", "xn--telegra-y03c", "xn--tlgram-bvab", "xn--tlgram-bhgb", "xn--telgram-v8a", "xn--telgram-ts4c", "xn--tlgram-p3ab", "xn--tlgram-ivab", "xn--telegrm-7fg", "xn--elegram-5jg", "xn--telegra-2id", "xn--telegrm-fn4c", "xn--telegam-vgg",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
