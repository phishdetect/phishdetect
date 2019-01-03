// PhishDetect
// Copyright (c) 2018-2019 Claudio Guarnieri.
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

// Skype brand properties.
func Skype() *Brand {
	name := "skype"
	original := []string{"skype"}
	whitelist := []string{"skype.com", "skype.net", "skype.org"}
	suspicious := []string{
		"skypea", "skypeb",
		"skypec", "skyped", "skypee",
		"skypef", "skypeg", "skypeh",
		"skypei", "skypej", "skypek",
		"skypel", "skypem", "skypen",
		"skypeo", "skypep", "skypeq",
		"skypes", "skypet",
		"skypeu", "skypev", "skypew",
		"skypex", "skypey", "skypez",
		"rkype", "qkype", "wkype",
		"ckype", "3kype", "sjype",
		"siype", "scype",
		"skxpe", "skqpe", "skipe",
		"sk9pe", "skyqe",
		"skyte", "skyxe", "sky0e",
		"skypd", "skypg", "skypa",
		"skypm", "skypu", "xn--ske-kzb97s",
		"xn--skp-hma793b", "xn--skp-lma293b", "xn--kpe-dfd2g",
		"xn--slcye-zva", "xn--skp-moa093b", "xn--skp-dma22s",
		"xn--skp-hma71s", "xn--skp-lma21s", "xn--slkyp-rsa",
		"xn--kyp-lma07c", "xn--sikye-6ce", "xn--sikyp-r51b",
		"xn--kyp-dhdb", "xn--kyp-dtd554q", "xn--ype-0xb9694c",
		"xn--sikye-zva", "xn--sye-pyc0b", "xn--slype-xbe",
		"xn--kpe-prd2682c", "s1cype", "xn--sikye-mme",
		"xn--kyp-tdd0n", "xn--ikype-esc", "xn--sky-hma87h",
		"xn--skp-moa532b", "xn--sye-1ed7372c", "xn--skp-xxcl",
		"xn--lkype-g2e", "xn--kyp-2ra50p", "xn--kyp-ura51p",
		"xn--kye-qoa6857c", "xn--kye-sbb1266c", "xn--kyp-mra52p",
		"xn--kyp-era53p", "xn--sky-dma8h", "xn--sky-hma3h",
		"xn--sky-lma8g", "xn--syp-6xcw", "xn--slcpe-sva",
		"xn--kyp-tdd531r", "xn--sky-2ra877a", "xn--sky-5qa345a",
		"xn--sky-era335a", "xn--sky-mra325a", "xn--sky-ura315a",
		"xn--sky-2ra305a", "xn--sky-mra897a", "xn--sky-era808a",
		"xn--kyp-ehd73c", "xn--kyp-dhd089q", "xn--sye-sbb74w",
		"xn--slcye-mme", "xn--skp-ura207b", "xn--skp-2ra296b",
		"xn--skp-era227b", "xn--syp-dma1107c", "xn--syp-hma6007c",
		"xn--syp-lma1007c", "xn--lkype-jjy", "xn--skp-5qa237b",
		"xn--slkyp-r51b", "xn--kyp-bza7078a", "xn--spe-jzb80m",
		"xn--skp-moa519b", "sllcype", "xn--ikype-jjy",
		"xn--lcype-esc", "xn--kpe-jzb742t", "xn--ske-1edo",
		"xn--ske-qoa81r", "xn--syp-5qa1086c", "xn--skp-dma249b",
		"xn--syp-era1976c", "xn--skp-lma239b", "xn--skp-hma739b",
		"xn--syp-ura1776c", "xn--syp-2ra1676c", "xn--kyp-2ra501v",
		"siikype", "xn--kye-qoa152v", "xn--sky-2ed4h",
		"xn--skype-h9x", "xn--sky-lma810b", "xn--sky-hma320b",
		"xn--sky-dma820b", "xn--sky-dma357a", "xn--sky-lma347a",
		"xn--sky-hma847a", "xn--sky-tdd8c", "xn--sky-roa9k",
		"xn--sky-roa9l", "xn--sky-roa9i", "xn--sye-qoa216a",
		"xn--sky-roa9j", "xn--sky-roa9h", "xn--kyp-lma54r",
		"xn--kyp-hma05r", "xn--kyp-dma55r", "xn--sikyp-f2e",
		"xn--syp-era694a", "xn--sky-tbb449a", "xn--ske-1ed86c",
		"xn--ske-sbb378a", "xn--sky-tbb42w", "xn--kpe-wxc2214c",
		"xn--sky-roa922b", "xn--scype-k7a", "xn--lcype-jjy",
		"xn--kyp-ljzu09f", "xn--sky-2ed93d", "xn--skp-era20q",
		"xn--skp-mra29p", "xn--slkpe-gze", "xn--skp-5qa21q",
		"xn--slcye-2tb", "xn--skp-ura28p", "xn--skp-2ra27p",
		"xn--skp-ura261b", "xn--skp-2ra251b", "xn--slcyp-59d",
		"xn--skp-5qa291b", "xn--skp-era281b", "xn--skp-mra271b",
		"xn--sikyp-flf", "xn--lkype-esc", "xn--ikype-g2e",
		"xn--kyp-bza229a", "xn--slkyp-f2e", "xn--slcye-6ce",
		"xn--slkyp-59d", "xn--kye-bza128a", "xn--kyp-ggq313f",
		"xn--skype-n4a", "xn--skp-6xc26j", "xn--kye-0xb64t",
		"xn--sky-6xc3d", "xn--slcye-yye", "xn--sky-6xc84a",
		"xn--slkye-mme", "xn--syp-dma617a", "xn--slkyp-3we",
		"xn--kyp-bza767a", "xn--kye-qoa67b", "xn--ske-moaf",
		"xn--spe-wxc3443c", "xn--sye-t5c7903c", "xn--skp-ura244a",
		"xn--skp-2ra234a", "xn--sikyp-3we", "xn--skp-era264a",
		"xn--skp-mra254a", "xn--spe-dfd3272c", "xn--ske-qoa875a",
		"xn--sky-lma37h", "xn--kpe-loa293b", "xn--sky-dma38h",
		"xn--kyp-ehd7984a", "xn--kpe-wxc787r", "xn--sky-2ra831b",
		"xn--kpe-bza55m", "xn--lcype-tcb", "xn--slkyp-flf",
		"xn--kyp-bza744b", "xn--slcyp-rsa", "xn--slcyp-lsa",
		"xn--slcyp-fsa", "xn--skp-moa5719a", "xn--skp-kzb58l",
		"xn--skype-k41s", "xn--slcyp-mza", "xn--slcyp-b0a",
		"xn--slcyp-yza", "xn--slcyp-z0a", "xn--slcyp-n0a",
		"xn--skp-6xc22e", "xn--ske-xxc95a", "xn--kye-0xb68p",
		"xn--kyp-5qa54p", "xn--kpe-loa752v", "s1kype",
		"xn--kyp-dhd5133c", "xn--ske-sbb35h", "xn--sky-5qa37f",
		"xn--sikpe-r9d", "xn--skype-wwb", "xn--ske-qoa892b",
		"xn--sky-mra35f", "xn--sky-era36f", "xn--kye-t5c67b",
		"xn--sky-ura34f", "xn--sikpe-gze", "xn--kyp-tdd0743c",
		"xn--kye-0xb11n", "xn--sye-pyc58d", "xn--skp-dma286a",
		"xn--skp-hma776a", "xn--skp-lma276a", "xn--slkpe-puc",
		"xn--kpe-dfd2043c", "xn--sky-roa985a", "xn--slkyp-n0a",
		"xn--ske-sbb31w", "xn--syp-mra684a", "xn--kyp-ura04a",
		"xn--kyp-0xb25m", "xn--kpe-bza511a", "xn--syp-5qa605a",
		"xn--ske-moa48g", "xn--syp-ura674a", "xn--syp-2ra664a",
		"slikype", "xn--ske-moa982b", "xn--slkye-6ce",
		"xn--ske-xxc91e", "xn--sky-2ra33f", "xn--kpe-dfd760r",
		"xn--syp-6xc1343c", "xn--ske-t5c88a", "xn--ske-jzc30j",
		"xn--kyp-dtd0972c", "xn--skype-hoc", "xn--siype-wj9c",
		"xn--ikype-tcb", "xn--syp-tdd1972c", "xn--kpe-bza573b",
		"xn--sye-jzc2733c", "xn--sky-roa483b", "xn--slype-zra",
		"xn--sky-ura887a", "xn--kpe-wxc22f", "xn--syp-pyc1765a",
		"xn--kpe-0xb00z", "xn--ske-qoa838b", "xn--slype-2ye",
		"silkype", "xn--skp-kzb50z", "xn--kye-jzc15e",
		"xn--skype-y3a", "xn--sky-5qa818a", "xn--skp-efd52d",
		"xn--kpe-0xb0e", "xn--slype-5xa", "xn--syp-dhd6362c",
		"xn--kye-1ed180r", "xn--skp-efd0g", "xn--kye-t5c6773c",
		"xn--sky-5qa871b", "xn--sky-mra851b", "xn--sky-era861b",
		"xn--kyp-lma543v", "xn--kyp-hma053v", "xn--kyp-dma553v",
		"xn--sky-ura841b", "xn--skp-kzb52s", "xn--syp-dtd1112c",
		"xn--kyp-dma094b", "xn--kyp-hma584b", "xn--kyp-lma084b",
		"xn--kyp-6xc0114c", "xn--kpe-jzb28t", "xn--skp-kzb08t",
		"xn--ype-z30b51a", "silcype", "xn--slcyp-r51b",
		"xn--skp-hma7g", "xn--skp-lma2g", "xn--skp-dma2h",
		"xn--sky-roa909b", "xn--slype-hxa", "xn--slkpe-sva",
		"xn--skp-tdd2e", "xn--scype-hoc", "xn--sky-tbb4028a",
		"xn--ype-oyc357r", "xn--kpe-prd725q", "xn--skype-zsa",
		"xn--ype-oyc88e", "xn--sky-kzc47j", "xn--skp-mra217b",
		"xn--skp-xxc5075a", "xn--skype-4nc", "xn--kyp-0xb27z",
		"xn--ype-ggq947p", "xn--skype-k7a", "xn--kyp-hma5867c",
		"xn--kpe-loa2957c", "xn--skp-moa5j", "xn--spe-loa816a",
		"xn--skp-moa5i", "xn--sikyp-59d", "xn--skp-moa5m",
		"xn--skp-moa5l", "xn--slkye-2tb", "xn--sikye-2tb",
		"xn--ske-moa456a", "xn--kyp-ura052b", "xn--kyp-2ra042b",
		"xn--ske-xxc4e", "xn--kyp-5qa082b", "xn--kye-bza681a",
		"xn--kyp-era072b", "xn--kyp-mra062b", "xn--skp-qrd5e",
		"xn--kye-jzc1504c", "xn--kye-bza164a", "xn--kpe-loa28b",
		"xn--ske-t5c82g", "xn--kyp-5qa541v", "xn--kyp-mra521v",
		"xn--kyp-era531v", "xn--sky-hma383b", "xn--sky-lma873b",
		"xn--kyp-ura511v", "xn--sky-dma883b", "xn--kye-qoa15q",
		"xn--kye-bza61c", "xn--kye-qoa683b", "xn--sky-kzc49c",
		"xn--skp-dhd76b", "xn--sky-u5c91a", "xn--ype-0xb47m",
		"xn--ype-bza941a", "xn--kye-jzc617r", "xn--ype-bza4446c",
		"xn--kyp-0xb29s", "xn--kyp-bza721a", "xn--sye-qoa7096c",
		"xn--kpe-bza538a", "xn--kyp-0xb74u", "xn--kpe-0xb06t",
		"xn--skp-dma204b", "xn--kye-sbb68g", "xn--slkye-zva",
		"xn--sky-kzc94e", "xn--skp-tdd22d", "xn--slkpe-r9d",
		"xn--lkype-569c", "xn--ske-kzb44m", "xn--sky-u5c47b",
		"xn--lkype-tcb", "xn--sky-tbb914a", "xn--sikyp-fsa",
		"xn--slcpe-r9d", "xn--sikyp-mza", "sllkype",
		"xn--slcpe-gze", "xn--ske-sbb333a", "xn--sikpe-yif",
		"xn--spe-jzb3094c", "xn--slcyp-3we", "xn--syp-pyc11k",
		"slkype", "xn--skp-kzb5617a", "xn--skp-efd5894a",
		"xn--sikyp-lsa", "xn--sikyp-rsa", "xn--slcyp-f2e",
		"xn--spe-wxc8a", "xn--ype-oyc8804c", "xn--syp-mra1876c",
		"xn--sky-tbb462a", "xn--kpe-ehd56b", "xn--kyp-5qa0847c",
		"xn--kyp-era0747c", "xn--kyp-mra0647c", "xn--kyp-ura0547c",
		"xn--kyp-2ra0447c", "xn--slype-hde", "xn--sky-u5c99g",
		"xn--syp-ljz875f", "xn--spe-loa3196c", "xn--lcype-569c",
		"xn--syp-lma607a", "xn--sky-6xc80e", "xn--slcpe-yif",
		"xn--syp-hma117a", "xn--kpe-0xb04m", "xn--spe-prd3812c",
		"xn--kyp-hma57c", "xn--slkyp-lsa", "xn--slkyp-fsa",
		"xn--kyp-dma08c", "xn--kye-1ed6143c", "xn--slcyp-flf",
		"xn--kye-t5c144r", "xn--sky-roa9619a", "xn--ikype-569c",
		"xn--ype-ehd4362c", "xn--syp-pyc68e", "xn--ske-kzb91p",
		"sikype", "xn--slcpe-puc", "xn--sikye-yye",
		"xn--slkye-yye", "xn--slype-lkb", "xn--siype-xbe",
		"xn--sky-u5c9535a", "xn--sky-kzc4365a", "xn--kyp-0xb2327a",
		"xn--sky-2ed9994a", "xn--skp-xxc54k", "xn--kpe-loa75q",
		"xn--slkyp-z0a", "xn--kyp-2ra03a", "xn--ske-moa929a",
		"xn--kpe-jzb2855c", "xn--slkyp-mza", "xn--kyp-5qa07a",
		"xn--skype-qbe", "xn--slkyp-b0a", "xn--kyp-mra05a",
		"xn--slkyp-yza", "xn--kyp-era06a", "xn--syp-pyc13d",
		"xn--kyp-6xc577r", "xn--skp-qrd5444a", "xn--sikpe-puc",
		"xn--skp-moa5k", "xn--kyp-dma0967c", "xn--spe-pyc99d",
		"xn--kyp-lma0867c", "xn--kyp-6xc01f", "xn--slkpe-yif",
		"xn--skp-5qa274a", "xn--sikpe-sva", "xn--skype-cta",
		"xn--skp-moa595a", "xn--sikyp-z0a", "xn--sikyp-n0a",
		"xn--sikyp-b0a", "xn--sikyp-yza", "xn--slype-wj9c",
		"xn--skp-xxc56d", "xn--kye-sbb124a", "xn--sye-pyc52a",
		"xn--skp-xxc02f", "xn--spe-pyc93j", "sicype",
		"xn--kye-sbb682u", "xn--sye-sbb2495c", "xn--ske-jzc36d",
		"xn--lcype-g2e", "xn--kye-1ed6h", "s-kype",
		"sk-ype", "sky-pe", "skyp-e",
		"smkype", "sk6ype", "sjkype",
		"skiype", "skxype", "sokype",
		"skmype", "skypme", "skjype",
		"skypoe", "skyple", "skyxpe",
		"skoype", "sksype", "skygpe",
		"sky7pe", "sklype", "skyspe",
		"skyhpe", "skyape", "skyp0e",
		"skyope", "skhype", "skgype",
		"skympe", "sk7ype", "skylpe",
		"sky6pe", "skuype", "sktype",
		"skaype", "skyupe", "skytpe",
		"sky0pe",
		"skyype", "sskype", "skyppe",
		"skkype", "skyme", "skypr",
		"skyoe", "skyps", "skypz",
		"zkype", "akype", "sk7pe",
		"skape", "sktpe", "slype",
		"skupe", "skspe", "skhpe",
		"xkype", "skyle", "skyp4",
		"skypw", "skgpe", "skyp3",
		"sk6pe", "ekype", "smype",
		"ykype", "dkype", "ksype",
		"sykpe", "skpye", "skyep",
		"skypi", "skypo", "skypecom",
	}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
