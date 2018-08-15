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

// Twitter brand properties.
func Twitter() *Brand {
	name := "twitter"
	original := []string{"twitter"}
	whitelist := []string{"twitter.com", "ads-twitter.com"}
	suspicious := []string{
		"twittera", "twitterb", "twitterc", "twitterd", "twittere", "twitterf", "twitterg", "twitterh", "twitteri", "twitterj", "twitterk", "twitterl", "twitterm", "twittern", "twittero", "twitterp", "twitterq", "twitterr", "twitters", "twittert", "twitter", "twitterv", "twitterw", "twitterx", "twittery", "twitterz", "uwitter", "vwitter", "pwitter", "dwitter", "4witter", "tvitter", "tuitter", "tsitter", "tgitter", "t7itter", "twhtter", "twktter", "twmtter", "twatter", "twytter", "twiuter", "twivter", "twipter", "twidter", "twi4ter", "twituer", "twitver", "twitper", "twitder", "twit4er", "twittdr", "twittgr", "twittar", "twittmr", "twittur", "twittes", "twittep", "twittev", "twittez", "twitteb", "twitte2", "xn--twittr-m4a", "xn--twittr-mye", "xn--twitte-15c", "xn--twitte-85c", "xn--twtter-j91a", "tvvitter", "xn--twtter-41c", "xn--twittr-04a", "xn--twtter-4r6v", "twltter", "xn--witter-orf", "xn--twittr-th8b", "xn--twittr-fvf", "xn--twittr-73a", "xn--twittr-t3a", "xn--witter-h1e", "xn--twiter-skb", "xn--twtter-j6b", "xn--witer-6dbc", "xn--twier-odea", "xn--twier-9dba", "xn--twtter-q9a", "xn--twtter-4va", "xn--twiter-srf", "tw1tter", "xn--wier-p6aca", "xn--twittr-f5a", "xn--twtter-cze", "xn--twittr-mva", "xn--witer-ldec", "xn--witter-okb", "xn--wier-p6dca", "xn--twittr-fhg", "xn--twier-9yea", "xn--twtter-jwa", "xn--twittr-tva", "xn--twiter-k1e", "xn--twittr-7of", "xn--twitte-855b", "xn--titter-i0g", "xn--wier-podca", "xn--twitte-uof", "xn--titter-3eh", "xn--witer-6yec", "xn--twiter-rkb", "xn--twtter-x8a", "xn--titter-wxf", "xn--twiter-rrf", "xn--twitte-u6c", "xn--twiter-l1e", "xn--twittr-fva", "t-witter", "tw-itter", "twi-tter", "twit-ter", "twitt-er", "twitte-r", "twiztter", "tw3itter", "twittedr", "tweitter", "twjitter", "twitt4er", "twirtter", "twitgter", "twittrer", "twuitter", "t3witter", "twittger", "twityter", "twitt6er", "twitte3r", "twi8tter", "twiktter", "twitrter", "tawitter", "twittder", "twxitter", "txwitter", "twitzter", "tw9itter", "twi5tter", "twiotter", "twitt3er", "twittezr", "twittyer", "twqitter", "twsitter", "twitt5er", "twkitter", "twittzer", "tewitter", "twittewr", "twittfer", "twaitter", "twiytter", "twit6ter", "tswitter", "twitte4r", "twoitter", "tqwitter", "twigtter", "twijtter", "twittesr", "t2witter", "twit5ter", "twiftter", "tw2itter", "twitfter", "tw8itter", "twi6tter", "twi9tter", "twiutter", "twittwer", "twittser", "twittr", "witter", "twitte", "twiter", "twtter", "titter", "twittter", "twiitter", "ttwitter", "twitteer", "twwitter", "twitrer", "ywitter", "t3itter", "twi6ter", "txitter", "twittet", "tqitter", "t2itter", "twjtter", "zwitter", "twittee", "twittef", "twittwr", "5witter", "twitted", "twizter", "twigter", "twitger", "twutter", "twit5er", "twitt4r", "tw9tter", "teitter", "6witter", "rwitter", "twitzer", "twit6er", "twitte5", "twotter", "twirter", "twitfer", "gwitter", "twi5ter", "twityer", "twitte4", "taitter", "twittsr", "twittzr", "tw8tter", "fwitter", "twittrr", "twiyter", "twifter", "twitt3r", "t.witter", "tw.itter", "twi.tter", "twit.ter", "twitt.er", "twitte.r", "wtitter", "tiwtter", "twtiter", "twitetr", "twittre", "twetter", "twittor", "twittir", "twittercom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
