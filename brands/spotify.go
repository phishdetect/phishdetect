// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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

package brands

// Spotify brand properties.
func Spotify() *Brand {
	name := "spotify"
	original := []string{"spotify"}
	safelist := []string{
		"spotify.com", "spotify.org", "spotify.it", "spotify.de", "spotify.fr",
		"spotify.nl", "spotify.es", "spotify.se", "spotify.no", "spotify.fi",
		"spotify.ru", "spotify.lt", "spotify.be", "spotify.pt", "spotify.net",
	}
	suspicious := []string{
		"spotifya", "spotifyb",
		"spotifyc", "spotifyd", "spotifye",
		"spotifyf", "spotifyg", "spotifyh",
		"spotifyi", "spotifyj", "spotifyk",
		"spotifyl", "spotifym", "spotifyn",
		"spotifyo", "spotifyp", "spotifyq",
		"spotifyr", "spotifys", "spotifyt",
		"spotifyu", "spotifyv", "spotifyw",
		"spotifyx", "spotifyy", "spotifyz",
		"rpotify", "qpotify", "wpotify",
		"cpotify", "3potify", "sqotify",
		"srotify", "stotify", "sxotify",
		"s0otify", "spntify", "spmtify",
		"spktify", "spgtify", "spouify",
		"spovify", "spopify", "spodify",
		"spo4ify", "spothfy", "spotkfy",
		"spotmfy", "spotafy", "spotyfy",
		"spotigy", "spotidy", "spotiby",
		"spotiny", "spotivy", "spotifx",
		"spotifq", "spotifi", "spotif9",
		"xn--sptlfy-j0e", "xn--sptif-7dc33y", "xn--potiy-dmb8319e",
		"xn--sptfy-kua460c", "xn--sptfy-7dc5042a", "xn--potfy-eta66e",
		"xn--sptfy-ywb664b", "xn--sotfy-6nc40z", "xn--spoif-ruc651a",
		"xn--sot1fy-brf", "xn--sp0tif-8xe", "xn--sptfy-kua00b",
		"xn--spoif-9db862c", "xn--s0tify-32b", "xn--sptfy-1sa27j",
		"xn--sptfy-ywb775a", "xn--sotfy-6nc91v", "xn--sotfy-wva70370a",
		"xn--sptlfy-qpg", "xn--spotf-2sa580c", "xn--pot1fy-2k2a",
		"xn--sptfy-p4a267d", "xn--sptfy-6nc8891c", "xn--sptiy-dmb881e",
		"xn--sotfy-03a611c", "xn--poify-esc07t", "xn--poify-8ye550z",
		"xn--soify-8db453b", "xn--sp0ify-rrf", "xn--potif-t9d2235e",
		"xn--potif-t9d3500a", "xn--spoty-dmb2053a", "xn--ptify-0ta471d",
		"xn--sptif-0if80m", "xn--ptify-tcb99l", "xn--sotfy-eta561c",
		"xn--otify-vva8710f", "xn--spotf-2sa140a", "xn--spotf-tbe73o",
		"xn--sptfy-6nc60v", "xn--potif-tcb913b", "xn--stify-jme1129b",
		"xn--potif-g2e94d", "sp0tlfy", "xn--sptfy-03a097d",
		"xn--sptif-ruc614c", "xn--s0tify-brf", "xn--sptiy-sce6s",
		"xn--spoty-q4a39d", "xn--spify-sce9a", "xn--ptify-tcb882c",
		"xn--sptfy-eta140d", "xn--spotf-tbe18g", "xn--sptiy-dmb010b",
		"xn--stify-jme39y", "xn--sptfy-j9xy31h", "xn--sotif-wva337d",
		"xn--soify-vyep", "xn--potif-ize4j", "xn--spo1fy-rkb",
		"xn--stify-jyen", "xn--ptify-jye3n", "xn--spify-nde0659b",
		"sp0t1fy", "xn--otify-ime4484e", "xn--ptify-tcb1883c",
		"xn--spotf-uva06w", "xn--sptfy-7dc37y", "xn--spotf-t9d25420a",
		"xn--sotfy-p4a880c", "xn--spify-8db7383c", "xn--sptfy-1ta7164a",
		"xn--ptify-rce2425e", "xn--soify-3ce81g", "xn--ptify-esc604b",
		"xn--sotiy-dmb320b", "xn--potlfy-hj9d", "xn--sptfy-03a4124c",
		"xn--spoif-9db420d", "xn--sotif-uva76k", "xn--spoiy-dmb640b",
		"xn--spofy-6nc24v", "xn--spot1f-8xe", "xn--spotly-7tb",
		"xn--stify-wva722f", "xn--ptify-uob659b", "xn--stify-ztb785b",
		"xn--spotlf-8xe", "xn--poify-tcb713c", "xn--spotf-fta538d",
		"xn--sotif-ruc63w", "xn--sptfy-ywb3703c", "xn--sptiy-6df99c",
		"xn--sptif-ruc83s", "xn--sptiy-dmb6h", "xn--sptfy-03a42f",
		"xn--potlfy-26c", "xn--stify-wva940c", "xn--ptify-jua4694a",
		"xn--sptlfy-ql8b", "xn--potiy-tcb216b", "xn--sptif-ruc0271c",
		"xn--potif-uva001d", "xn--otify-ime46d", "xn--sptfy-eta8464c",
		"xn--sotlfy-wcf", "xn--sptif-kye2b", "xn--sptlfy-xqf",
		"xn--otify-ime575z", "xn--spoti-uva562c", "xn--potiy-esc128a",
		"xn--spify-7dc138a", "xn--sp0tif-u9c", "xn--spoif-t9d21h",
		"xn--stify-ztb0813c", "xn--sptfy-6nc60v", "xn--sptfy-6nc875b",
		"xn--spify-nde05r", "xn--spotf-zwb405b", "xn--sp0ify-rkb",
		"xn--potfy-g2e32310a", "xn--ptify-jua91e", "xn--sptif-kua230d",
		"xn--spotf-ruc89r", "xn--potif-tcb57s", "xn--spoty-6df911y",
		"xn--sptfy-6nc593a", "xn--potfy-eta002d", "xn--sotfy-1sa971c",
		"xn--ptify-isf0713e", "xn--soify-nde67a", "xn--potlfy-hvf",
		"xn--ptify-6dc39c", "xn--sotiy-ztb119a", "xn--sptfy-p4a868e",
		"xn--sptfy-1ta26m", "xn--potif-ruc6637e", "xn--potif-ruc7902a",
		"xn--sotfy-ywb974b", "xn--stify-ztb678d", "xn--potif-uva13y",
		"xn--otify-uye0m", "xn--potfy-j9x1r", "xn--sptfy-p4a2714c",
		"xn--potfy-6nc4367e", "xn--sotfy-1sa465c", "xn--sptiy-sce00m",
		"xn--sptiy-kye11d", "xn--sptiy-kua195d", "xn--stify-wva839c",
		"xn--sotfy-wva54a", "xn--ptify-g2e73h", "xn--spofy-p4a36a",
		"xn--stify-jme78n", "xn--sotfy-vye96410a", "xn--sptif-ruc721a",
		"xn--ptify-tcb993b", "xn--sptif-kua887d", "xn--sptiy-kye11d",
		"xn--spify-nde4759b", "xn--spify-vob349a", "xn--potfy-tcb70q",
		"xn--sotiy-3ce78l", "xn--sptfy-03a0024c", "xn--soify-8db342c",
		"xn--sptif-t9d6769b", "xn--sptfy-03a817b", "xn--sptif-ruc83s",
		"xn--spotf-uva01370a", "xn--sotiy-dmb804b", "xn--spoiy-zhe91e",
		"xn--sp0tfy-61c", "xn--spotf-zwb062c", "xn--ptify-rce379z",
		"xn--sptfy-1sa66t", "xn--sptif-t9d4f", "xn--sotif-t9d29b",
		"xn--spoty-zwb360c", "xn--ptify-uob7673a", "xn--sptif-kye80f",
		"xn--sptif-uva25s", "xn--spotlf-u9c", "xn--sptfy-eta85j",
		"xn--spotly-07f", "xn--spify-sce13g", "xn--pot1fy-26c",
		"xn--spt1fy-jqc", "xn--spoti-uva65h", "xn--stify-rcen",
		"xn--ptify-0ta50z", "xn--potfy-tcb953b", "xn--ptify-esc43t",
		"xn--spotf-fta970d", "xn--spotf-2sa7i", "xn--spoty-6df58800a",
		"xn--sptfy-03a81p", "xn--potiy-dmb98n", "xn--sp0tif-neg",
		"xn--sptlfy-4l8b", "xn--sptiy-vob021b", "xn--soify-3cew",
		"xn--potif-esc45s", "xn--sptfy-03a706c", "xn--poify-nde62h",
		"xn--sptfy-ywb557d", "xn--potlfy-2k2a", "xn--spotf-q4a373d",
		"xn--spofy-ode53320a", "xn--sotlfy-brf", "xn--sptif-sce14g",
		"xn--spt1fy-xxa", "xn--sptif-7dc795b", "xn--stify-jme40c",
		"xn--sotif-vyez", "xn--sotfy-ztb60j", "xn--ptify-g2e1658b",
		"xn--sptfy-kye28410a", "xn--stify-6dc213a", "xn--spoti-t9d70a",
		"xn--spofy-9ye786y", "xn--spofy-03a19a", "xn--sptfy-sce17320a",
		"xn--sotif-t9d69g", "xn--stify-rce21b", "xn--sptif-1ta350d",
		"xn--sp0tfy-lwa", "xn--spo1fy-rrf", "xn--potfy-1sa54z",
		"xn--stify-uob603b", "xn--sptiy-zhe7939b", "xn--potfy-tcb1983a",
		"xn--sptfy-1sa8464c", "xn--spt1fy-ql8b", "xn--sptfy-sbe34g",
		"xn--sptfy-1sa661c", "xn--sptfy-6nc2002c", "xn--otify-tcb103c",
		"xn--ptify-uob78m", "xn--spoti-ruc527a", "xn--sptif-uva4354c",
		"xn--sotif-uva054c", "xn--sptlfy-cmh", "xn--sptif-uva250c",
		"xn--p0tify-2k2a", "xn--sptiy-kua80i", "xn--sotfy-ztb5j",
		"xn--stify-vye3968b", "xn--ptify-esc0381c", "xn--spotf-13a736b",
		"xn--sptfy-sbe34g", "xn--poify-8db02r", "xn--sotif-vye59e",
		"xn--sptfy-kua6954a", "xn--sptfy-kua14m", "xn--pot1fy-hvf",
		"xn--potfy-6nc455a", "xn--sptiy-dmb998b", "xn--spofy-sbe27g",
		"xn--potfy-sbe2825e", "xn--sotif-ztb47l", "xn--soify-8db937b",
		"xn--spoiy-9db355b", "xn--ptify-tcb775e", "xn--sptfy-1sa550d",
		"xn--sptfy-eta0a", "xn--sotiy-jme20i", "xn--sptfy-sbe0569b",
		"xn--spotf-q4a716c", "xn--spoiy-9db728c", "xn--spotf-7nc1y",
		"xn--spoty-dmb86260a", "xn--stify-ztb896a", "xn--spoty-dmb74b",
		"xn--sotif-3ce48n", "xn--stify-jyen", "xn--stify-rcen",
		"xn--sptiy-zhe970a", "xn--sptfy-1ta12b", "xn--ptify-jua3320f",
		"xn--spoif-ode50g", "xn--spoty-dmb079a", "xn--sotif-wva779c",
		"xn--sptfy-kye617y", "xn--spify-8db3283c", "xn--spoty-13a039b",
		"xn--otify-vva890d", "xn--sotfy-03a137b", "xn--spoty-zhe95120a",
		"xn--sp0tfy-l6b", "xn--potif-uva1194a", "xn--potif-uva0810f",
		"xn--spoti-emb929a", "xn--potif-esc0h", "xn--poify-8db0024a",
		"xn--sptfy-mkg724w", "xn--potfy-1sa4920f", "xn--sptfy-1ta38370a",
		"xn--p0tify-2ib", "xn--sot1fy-iza", "xn--spot1y-07f",
		"xn--spolfy-rkb", "xn--sptiy-sce6s", "xn--sotfy-eta450d",
		"xn--spofy-eta881c", "xn--sptiy-zhe3839b", "xn--spoif-9yej",
		"xn--sotif-ruc041a", "xn--sptfy-g91bz822h", "xn--sptiy-6df50o",
		"xn--stify-3ce2859b", "xn--sptfy-1sa2664c", "xn--sptfy-6nc593a",
		"xn--spify-kye2a", "xn--potif-uva66d", "xn--spot1f-neg",
		"xn--ptify-rce26h", "xn--spify-8ye2968b", "xn--sptfy-ywb77d",
		"xn--sptif-uva8454c", "xn--potfy-569c3464f", "xn--potfy-j9xq59t",
		"xn--sptfy-1ta580c", "xn--sp0tif-gza", "xn--poify-8ye4234e",
		"xn--sptif-0if20b", "xn--sptfy-03a817b", "xn--potiy-6df684y",
		"xn--sptiy-dmb998b", "xn--spify-kua220d", "xn--spoti-ruc15u",
		"xn--soify-ztb437a", "xn--spoty-13a402d", "xn--spify-vob528b",
		"xn--sptif-vob195c", "xn--spotf-ize876y", "xn--spify-8db74b",
		"xn--sptfy-kua21x", "xn--sotfy-03a33h", "xn--sptfy-sbe4b",
		"xn--sptiy-zhe09d", "xn--otify-2ce94h", "xn--sotif-ztb816a",
		"xn--stify-jua700d", "xn--spoti-emb58o", "xn--potfy-esc49s",
		"xn--potfy-03a23a", "xn--sptif-t9d38g", "xn--ptify-jye480z",
		"xn--spoty-7nc81x", "xn--spotlf-gza", "xn--spoty-fta463c",
		"xn--sptif-7dc98d", "xn--sptfy-kua82b", "xn--spotf-0if229x",
		"xn--sptif-vob538b", "xn--sptfy-eta422e", "xn--sptfy-sbe4b",
		"xn--sotfy-eta76l", "xn--sotif-ztb283c", "xn--sptfy-1sa661c",
		"xn--ptify-281bo28h", "xn--spoty-zwb987a", "xn--sptif-ize85i",
		"xn--ptify-rce379z", "xn--sptif-uva250c", "xn--stify-vye7078b",
		"xn--potfy-1sa5205a", "xn--spotf-ruc69440a", "xn--sotfy-ztb65950a",
		"xn--sptfy-sce506z", "xn--spotly-m6e", "xn--sotlfy-w0e",
		"xn--sotiy-wva635d", "xn--sotiy-dmb52a", "xn--spify-8ye8768b",
		"xn--s0tify-w0e", "xn--sptif-uva149c", "xn--potfy-p4a40a",
		"xn--soify-ztb616b", "xn--sotfy-1sa0j", "xn--spoiy-9db44a",
		"xn--stify-uob3s", "xn--spify-8db032c", "xn--ptify-lkg597w",
		"xn--sptlfy-jqc", "xn--poify-nde739z", "xn--spotf-7nc52u",
		"xn--stify-ztb4913c", "xn--spoty-tbe04m", "xn--potlfy-2ib",
		"xn--spify-sce13g", "xn--potfy-tcb75660a", "xn--stify-0ta0f",
		"xn--sotfy-3ce295z", "xn--spotfy-l2c", "xn--ptify-esc215c",
		"xn--spt1fy-4l8b", "xn--spoif-ode16n", "xn--stify-3ce98f",
		"xn--stify-3ce872a", "xn--ptify-tcb174d", "xn--spofy-ywb316a",
		"xn--soify-wva22e", "xn--spotf-7nc334a", "xn--soify-wva769c",
		"xn--spotf-q4a56v", "xn--sptlfy-j0e", "xn--sp0tfy-eze",
		"xn--spoty-fta836d", "xn--spify-kua77e", "xn--spoif-ruc47s",
		"xn--sptiy-zhe37p", "xn--potfy-1sa08e", "xn--sotfy-wva37a",
		"xn--potfy-sbe3100a", "xn--spotf-uva210c", "xn--stify-uob018b",
		"xn--sptiy-kua713c", "xn--ptify-0ta4520f", "xn--spify-8db143b",
		"xn--sptif-t9d66s", "xn--sptfy-03a698e", "xn--spoti-ize37c",
		"xn--sotif-3ce82g", "xn--sotiy-wva35h", "xn--spotf-uva84a",
		"xn--spofy-9db2383a", "xn--stify-ztb785b", "xn--poify-8db9649e",
		"xn--sptfy-1ta33x", "xn--ptify-esc6181c", "xn--potiy-dmb9683a",
		"xn--sotfy-sbe65g", "xn--spt1fy-xqf", "xn--sptif-vob728a",
		"xn--sptiy-1ta833c", "xn--sotfy-6nc804a", "xn--sp0tfy-l91a",
		"xn--sptfy-sbe233a", "xn--sptlfy-xxa", "xn--sotif-ztb626b",
		"xn--spofy-eta070d", "xn--spofy-9ye35410a", "xn--sptfy-p4a096b",
		"xn--p0tify-26c", "xn--spify-8db143b", "xn--stify-0ta931c",
		"xn--potfy-g2e755y", "xn--sp0tfy-6r6v", "xn--ptify-jjyw49g",
		"xn--spotf-t9d686z", "xn--spify-kua041c", "xn--spify-8db915e",
		"xn--sptfy-7dc17150a", "xn--spoif-uva52e", "xn--potif-tcb380d",
		"xn--sptfy-p4a096b", "xn--otify-vva46d", "xn--spofy-1sa93f",
		"xn--potfy-esc29540a", "xn--spofy-9db003b", "xn--sptlfy-cxa",
		"xn--stify-wva5454c", "xn--sptfy-1sa550d", "xn--stify-jua305c",
		"xn--spoti-7df0r", "xn--otify-esc74t", "xn--spofy-eta52f",
		"xn--otify-2ce069z", "xn--ptify-jye480z", "xn--potiy-tcb688c",
		"xn--otify-vva92y", "xn--spofy-p4a627b", "xn--ptify-jye3n",
		"xn--potfy-sbe20i", "xn--sotif-ruc15s", "xn--spotf-fta720a",
		"xn--potfy-jjys332k", "xn--sotif-uvac", "xn--sotiy-ztb581c",
		"xn--p0tify-hvf", "xn--spot1y-m6e", "xn--otify-tcb797b",
		"xn--sotfy-ywb579a", "xn--sptiy-7dc621a", "xn--p0tify-hj9d",
		"xn--stify-jme7919b", "xn--spoty-2sa96i", "xn--sptlfy-4wb",
		"xn--potiy-g2e25b", "xn--sptiy-zhe09d", "xn--sptfy-6nc486c",
		"xn--pot1fy-2ib", "xn--sptfy-03a706c", "xn--sptfy-kua26370a",
		"xn--sptfy-1sa5d", "xn--spotf-7nc981b", "xn--sptif-sce79n",
		"xn--spify-8db032c", "xn--spoty-zhe393z", "xn--soify-nde08f",
		"xn--stify-ztb077c", "xn--spofy-03a457b", "xn--ptify-uob6309e",
		"xn--sptfy-p4a6814c", "xn--stify-jua02l", "xn--spofy-03a636c",
		"xn--sptfy-kye617y", "xn--potfy-eta13z", "xn--sptif-kye80f",
		"xn--spofy-1sa480d", "xn--spot1y-7tb", "xn--sp0tfy-s9a",
		"xn--spoif-t9d0j", "xn--stify-wva121e", "xn--spotf-q4a906b",
		"xn--spotfy-6db", "xn--sptfy-ywb664b", "xn--potif-esc810b",
		"xn--sotiy-dmb219b", "xn--sptiy-6df3218b", "xn--potfy-03a79u",
		"xn--potiy-zhe067z", "xn--sptif-t9d4f", "xn--stify-0ta14l",
		"xn--spoif-9ye97e", "xn--potfy-1sa412d", "xn--sotfy-ztb856a",
		"xn--sptif-kua08z", "xn--sotfy-3ce85320a", "xn--sptiy-1ta92i",
		"xn--spoti-0he48l", "xn--spofy-ywb594b", "xn--spoti-emb739b",
		"xn--stify-ztb89e", "xn--sptfy-p4a975c", "xn--sptlfy-xqf",
		"xn--sptfy-ywb9503c", "xn--sptif-vob38n", "xn--ptify-jye3534e",
		"xn--spofy-6nc424a", "xn--sptfy-ywb775a", "xn--sptfy-1ta94b",
		"xn--ptify-tcb5983c", "xn--sptif-7dc148a", "xn--spify-sce9a",
		"xn--poify-8db983c", "xn--stify-jua811c", "xn--spotf-t9d4b",
		"xn--sptfy-p4a975c", "xn--sptiy-sce00m", "xn--spotf-13a546c",
		"xn--sp0tfy-z8a", "xn--spotf-ize44410a", "xn--sptfy-eta25t",
		"xn--sotfy-ztb0913a", "xn--spt1fy-j0e", "xn--sptif-ruc013b",
		"xn--spotf-uva98l", "xn--spotf-13a104d", "xn--stify-3ce98f",
		"xn--potfy-6nc5632a", "xn--sptiy-dmb2943c", "xn--ptify-tcb993b",
		"xn--sotfy-wva1454a", "xn--ptify-g2e34s", "xn--sptif-1ta540c",
		"xn--spotf-0if88600a", "xn--spt1fy-j0e", "xn--sptiy-dmb010b",
		"xn--sptfy-eta4364c", "xn--ptify-jua48y", "xn--sptfy-vob51l",
		"xn--spoti-0he82e", "xn--spoti-emb396c", "xn--spoif-uva079c",
		"xn--sotfy-vye307y", "xn--sptif-uva149c", "xn--stify-wva839c",
		"xn--spolfy-rrf", "xn--spo1fy-k1e", "xn--spotf-ruc0371a",
		"xn--otify-2ce9225e", "xn--potfy-p4a96u", "xn--potif-esc262a",
		"xn--ptify-6dc2408e", "xn--spoty-q4a209b", "xn--ptify-isf109x",
		"xn--sp0tfy-6va", "xn--otify-ytb87k", "xn--spotf-13a39v",
		"xn--spoti-uva935d", "xn--spoty-2sa256d", "xn--soify-jme33c",
		"xn--sotfy-03a026c", "xn--sotfy-jme702z", "xn--spoiy-ode0p",
		"xn--sp0tiy-m6e", "xn--sotfy-1sa860d", "xn--sptif-1ta7e",
		"xn--ptify-f91by18h", "xn--otify-esc632a", "xn--sot1fy-w0e",
		"xn--potfy-p4a8189e", "xn--sotfy-wva900c", "xn--sptif-kua6c",
		"xn--sotif-t9d7g", "xn--spotf-fta170c", "xn--spt1fy-cxa",
		"xn--stify-wva94s", "xn--sot1fy-wcf", "xn--otify-vva9094a",
		"xn--spofy-9db84p", "xn--spify-7dc94z", "xn--sotfy-jme37910a",
		"xn--soify-8db65d", "xn--potif-ruc682a", "xn--spoty-13a12e",
		"xn--ptify-jjyq59g", "xn--poify-8ye4k", "xn--potfy-esc6281a",
		"xn--potfy-ywb65j", "xn--sptif-sce14g", "xn--ptify-esc43t",
		"xn--sotiy-vye89c", "xn--sotif-jme34c", "xn--spify-nde76f",
		"xn--sptif-ize8668b", "xn--spify-nde652a", "xn--sotfy-p4a50h",
		"xn--poify-tcb534b", "xn--sptfy-sbe62s", "xn--sptiy-dmb01i",
		"xn--potiy-tcb30b", "xn--sptiy-1ta216d", "xn--spotf-2sa948d",
		"xn--stify-rce21b", "xn--potiy-zhe9205e", "xn--sotfy-wva75w",
		"xn--spoti-t9d18m", "xn--spt1fy-xqf", "xn--spify-1ta161c",
		"xn--spify-8db14l", "xn--potfy-03a6489e", "xn--spoif-uva880c",
		"xn--sotlfy-32b", "xn--sptfy-vob768a", "xn--sotfy-p4a295c",
		"xn--spoty-fta55i", "xn--ptify-jua351d", "xn--sotfy-eta055c",
		"xn--sptif-uva032f", "xn--stify-wva1354c", "xn--potif-ize4134e",
		"xn--ptify-jye3534e", "xn--sptif-1ta100a", "xn--ptify-esc322a",
		"xn--spofy-p4a806c", "xn--potfy-03a667c", "xn--spoty-7nc299a",
		"xn--sotlfy-iza", "xn--sptfy-sce17320a", "xn--spolfy-k1e",
		"xn--spt1fy-cmh", "xn--sptfy-jsf335x", "xn--sptiy-6df9018b",
		"xn--spotlf-neg", "xn--sptfy-1sa443f", "xn--spotf-uva67a",
		"xn--otify-tcb41e", "xn--stify-3ce6959b", "xn--ptify-6dc269a",
		"xn--potiy-zhe94f", "xn--otify-ytb747b", "xn--sotiy-zhe9p",
		"xn--sptfy-mkg3919z", "xn--otify-ytb8553a", "xn--sptfy-eta140d",
		"xn--sptfy-j9x421h", "xn--sptfy-kye28410a", "xn--spotf-2sa390d",
		"xn--sotif-wva52z", "xn--sotif-uva560c", "xn--spotf-fta3h",
		"xn--sptif-kua420c", "xn--spot1f-u9c", "xn--stify-ztb896a",
		"xn--spofy-9db77e", "xn--stify-wva55i", "xn--sotif-jme99j",
		"xn--ptify-6dc3772a", "xn--sptif-sce79n", "xn--potfy-p4a837c",
		"xn--spify-8ye86i", "xn--spotf-zwb694a", "xn--stify-0ta425c",
		"xn--sptiy-7dc004b", "xn--poify-nde6025e", "xn--sptif-ize46t",
		"xn--spify-kye2a", "xn--sptif-0if2197b", "xn--ptify-0ta5894a",
		"xn--sotfy-ywb095a", "xn--sotfy-sbe25b", "xn--spoif-9db61s",
		"xn--sptfy-vob9933a", "xn--sotfy-p4a307b", "xn--pot1fy-hj9d",
		"xn--spot1f-1rf", "xn--ptify-g2e7458b", "xn--sptif-t9d273a",
		"xn--spoiy-dmb829b", "xn--sptif-t9d38g", "xn--stify-rce61g",
		"xn--spoty-tbe6w", "xn--sotiy-wva262c", "xn--otify-ytb7288e",
		"xn--poify-tcb2d", "xn--potiy-6df5573e", "xn--stify-6dc618a",
		"xn--sptif-uva421e", "xn--s0tify-iza", "xn--ptify-lkg4602e",
		"xn--sptif-0if6297b", "xn--sotiy-3ce3r", "xn--stify-vye38i",
		"xn--stify-3ce27r", "xn--sptfy-381bp922h", "xn--sp0ify-k1e",
		"xn--sptif-uva85i", "xn--sptfy-1sa4b", "xn--spotlf-1rf",
		"xn--spify-1ta340d", "xn--sptfy-sce506z", "xn--potfy-eta0820f",
		"xn--spoiy-9ye28c", "xn--sot1fy-32b", "xn--ptify-esc322a",
		"xn--spoty-2sa873c", "xn--spify-8db314d", "xn--potfy-p4a9454a",
		"xn--sptif-1ta908d", "xn--spt1fy-qpg", "xn--spofy-1sa202c",
		"xn--s0tify-wcf", "xn--sotfy-wva68l", "xn--sptif-ruc4371c",
		"xn--ptify-tcb882c", "xn--stify-0ta820d", "xn--sp0tiy-7tb",
		"xn--potif-0if8553e", "xn--potif-0if982y", "xn--otify-uye0434e",
		"xn--spt1fy-4wb", "xn--ptify-rce26h", "xn--sptfy-7dc12b",
		"xn--potfy-ywb526b", "xn--potif-t9d24i", "xn--sptfy-eta251c",
		"xn--spot1f-gza", "xn--sptif-kye2b", "xn--ptify-tcb50c",
		"xn--sotif-uva459c", "xn--otify-uye170z", "xn--sptfy-eta033f",
		"spot1fy", "xn--potfy-03a7754a", "xn--sptfy-sbe6369b",
		"xn--spoty-dmb81m", "xn--stify-uob129a", "xn--stify-jme40c",
		"xn--potif-tcb723c", "xn--spoty-q4a671d", "xn--spofy-9db89560a",
		"xn--sptfy-eta251c", "xn--potfy-ywb5078e", "xn--soify-wva580c",
		"xn--sotif-wva969b", "xn--sptfy-p4a69e", "xn--sptfy-eta1c",
		"xn--ptify-rce2425e", "xn--potfy-eta1105a", "xn--sptfy-ywb946c",
		"xn--potfy-ywb6343a", "xn--spify-nde76f", "xn--sptfy-vob56160a",
		"xn--stify-jua9c", "xn--potfy-tcb63f", "xn--potiy-dmb850c",
		"xn--spify-1ta89e", "xn--spify-8ye47t", "xn--potiy-esc74v",
		"xn--sptfy-1sa832e", "xn--potif-ize540z", "xn--sotfy-1sa18l",
		"xn--spofy-sbe0f", "xn--sptif-ruc721a", "xn--sotiy-zhe30e",
		"xn--sptfy-jsf99200a", "xn--spotf-uva4454a", "xn--spoiy-ode46l",
		"xn--otify-tcb214b", "xn--sptif-t9d0969b", "xn--stify-wva940c",
		"xn--spoif-9db062b", "xn--sptiy-dmb6053c", "xn--ptify-0ta04e",
		"xn--stify-rce61g", "xn--poify-esc252a", "xn--sptiy-dmb280d",
		"xn--sotfy-sbe7c", "xn--stify-vye98t", "xn--sp0tif-1rf",
		"xn--otify-esc23x", "xn--sptfy-vob44a", "xn--sptiy-vob493c",
		"xn--sp0tiy-07f", "xn--sotfy-eta6h", "xn--spotf-zwb25k",
		"xn--stify-6dc72z", "xn--sptfy-p4a09o", "xn--sptif-ize2868b",
		"xn--potfy-6nc5o", "xn--spofy-ode965z", "s-potify",
		"sp-otify", "spo-tify", "spot-ify",
		"spoti-fy", "spotif-y", "spotifdy",
		"spoti8fy", "spotiofy", "s0potify",
		"sp9otify", "spotzify", "spmotify",
		"spotijfy", "spotgify", "spotrify",
		"spot9ify", "spotikfy", "spotigfy",
		"spotjify", "spoftify", "spoktify",
		"spoltify", "spotfify", "sportify",
		"spotifty", "sopotify", "spotuify",
		"spoptify", "spotoify", "splotify",
		"spoytify", "slpotify", "spkotify",
		"spotifcy", "spot8ify", "spotitfy",
		"sp0otify", "spotifvy", "spoitify",
		"sppotify", "spotiufy", "spotidfy",
		"spoztify", "spootify", "spo6tify",
		"spotyify", "spotifgy", "spot6ify",
		"spotivfy", "spogtify", "spo5tify",
		"spotkify", "spot5ify", "spo0tify",
		"spotifry", "spoti9fy", "spo9tify",
		"spoticfy", "smpotify", "spotirfy",
		"spiotify", "sptify", "spotfy",
		"sotify", "spotiy", "potify",
		"spotif", "spoify", "spotiify",
		"spottify", "spotiffy", "sspotify",
		"dpotify", "spofify", "spotift",
		"spoyify", "spptify", "spogify",
		"spotjfy", "epotify", "zpotify",
		"spotifs", "spot8fy", "spotifu",
		"spo5ify", "sp9tify", "spotifh",
		"spot9fy", "ypotify", "spotofy",
		"spotifg", "smotify", "spotif6",
		"spitify", "slotify", "spotity",
		"sp0tify", "spotiry", "spotifa",
		"spotufy", "spltify", "apotify",
		"spoticy", "spotif7", "sporify",
		"xpotify", "spo6ify", "spozify",
		"sootify",
		"psotify", "soptify",
		"sptoify", "spoitfy", "spotfiy",
		"spotiyf", "sputify", "spatify",
		"spotefy", "spetify", "spotifycom",
	}
	exclusions := []string{"shopify"}

	return &Brand{
		Name:       name,
		Original:   original,
		Safelist:   safelist,
		Suspicious: suspicious,
		Exclusions: exclusions,
	}
}
